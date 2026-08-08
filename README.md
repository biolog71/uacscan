# uacscan

Collects [UAC](https://github.com/tclahr/uac)'s offline artifacts from a mounted
image in **one** filesystem pass.

UAC runs one `find(1)` per artifact entry. Across the current corpus that is 490
offline entries, twenty of which start at `/` and traverse the whole tree, so on
a large image the same inodes are visited dozens of times. `uacscan` compiles
every artifact into a predicate, walks the tree once, and evaluates all of them
against a single `statx` result per file.

Only the four offline collectors are in scope — `file`, `find`, `stat`, `hash`.
The 661 `command` entries execute on a live system and are not something a walk
can replace.

## Status

Output is byte-comparable with the shell implementation. The differential
harness compares them on every run:

| Tree | Entries | Result |
|---|---|---|
| synthetic fixture | 55 | all outputs agree |
| `/usr/share/doc` | 12,336 | all outputs agree |
| `/usr/lib/python3` | 25,541 | all outputs agree, 14.9× faster |

"Agree" means the bodyfile matches on inode, mode string, uid, gid, size, mtime,
ctime and birth time; the `find` path lists match as sets; the hash lists match
digest for digest; and collected files match by content hash.

## Usage

```bash
go build -o uacscan ./cmd/uacscan
```

```bash
./uacscan -m /mnt/image -o ./out -include 'bodyfile/*,system/*'
```

No path to a UAC checkout is needed — the artifact definitions are compiled
into the binary. Copy the executable to an examiner workstation and it works.

Key flags: `-m` mount point, `-o` output directory, `-include`/`-exclude`
artifact globs, `-start-date-days`/`-end-date-days` for the date range,
`-buffer-limit` for the small-file threshold, `-version` to see which UAC
corpus is baked in. To run against a newer or modified checkout instead of the
embedded copy, pass `-a /path/to/uac/artifacts` (which also switches `uac.conf`
to that checkout's, so definitions and configuration never come from different
places); `-c` overrides the config file on its own.

## Embedded artifact definitions

UAC's `artifacts/`, `config/` and `profiles/` are packed into a single
`tar.gz` — 428 files, 319 KiB of YAML compressing to 49 KiB — and embedded with
`go:embed`. Total binary: about 3.7 MB.

It is unpacked **into memory** at first use, never onto disk. An acquisition
tool has no business scattering temporary files across the examiner's machine,
and there is no reason to: the whole corpus is smaller than a single collected
log file. Loading goes through `fs.FS`, so the embedded copy and a real
directory (`os.DirFS`) run through identical code.

A `VERSION` file rides along recording the UAC release and commit the corpus
was built from, reported by `-version` and printed on every run. For a forensic
tool that provenance is not optional: a collection must be traceable to the
definitions that produced it.

```bash
./uacscan -version
# uacscan (embedded UAC artifacts 3.3.0, commit 7376467)
```

```bash
./uacscan -extract ./defs    # write the definitions out to read or edit
```

Regenerate after updating the UAC checkout:

```bash
go generate ./internal/uacdata
```

The archive is deterministic — entries sorted, timestamps and ownership
zeroed — so the same checkout always yields an identical blob and therefore a
reproducible binary. `TestEmbeddedMatchesCheckout` fails if the embedded copy
has drifted from a UAC checkout it can find, which is the only thing that would
catch a forgotten `go generate`.

## Running the comparison

```bash
go test ./...
```

```bash
go run ./test/harness -image /usr/share/doc -v
```

The harness builds a fixture image (or takes `-image`), runs both tools over it,
and reports every difference. It is also wired into `go test`.

The harness needs a checkout of [UAC](https://github.com/tclahr/uac), because it
runs the real shell implementation. It deliberately reads that checkout's
artifacts for both sides of the comparison rather than the embedded copy, so
the two tools are provably given the same definitions. It is found
automatically when the two live side by side:

```
parent/
  uac/       <- github.com/tclahr/uac
  uacscan/   <- this repository
```

Otherwise set `UAC_ROOT=/path/to/uac`. Only the harness needs it — the parser
and rule-compiler tests run against the embedded corpus and never skip — and the
tests that do need it skip cleanly, so `go test ./...` works on a machine that
has nothing but this repository.

## Design

**One stat per file, not one per rule.** The exported collector interface is
`InspectFile(path string) error` plus `ScanResults() (any, error)`. A path, not
a stat buffer — but no collector ever calls stat. The walker resolves each path
once and primes a single-entry cache; since every collector is called for the
same path consecutively, the cache hits every time. Without it, 479 compiled
rules would mean 479 stat calls per file.

**`statx`, not `lstat`.** Measured same-or-faster, and it carries birth time and
`STATX_ATTR_IMMUTABLE`. That last one removes the `FS_IOC_GETFLAGS` ioctl the
`immutable_files` artifact would otherwise need — and with it the only reason to
hold an open descriptor during the metadata phase.

**No descriptor in the file record.** Speculatively opening every file measured
~2.65 µs against ~1.45 µs for `statx` alone, and opening device nodes found in a
mounted image would reach the *examiner's* hardware. The open happens last, only
after a rule matched, and only for regular files.

**One open shared by all consumers, but never the descriptor itself.** A file
offset is shared state: hand out a `*os.File` and the second collector to call
`Read` sees an empty file. Worse, a collector that closes it causes the number
to be recycled, after which a retained reference silently reads a *different*
file into the evidence output. Collectors get a revocable `ReadAt`-only view
instead. Files below `-buffer-limit` are read into one reusable buffer — measured
at the same cost as a streaming tee, but with random access for free — and larger
ones stay on the descriptor.

**Results stream to disk.** A bodyfile for a million-inode image is well over a
hundred megabytes and is one of hundreds of outputs, so nothing accumulates in
memory. Each output target gets an append-only file in UAC's own line format,
which keeps the output tree readable by the same downstream tools and makes the
comparison a straight diff. `ScanResults` returns an `iter.Seq2` that reads it
back.

**Unreadable files are results, not errors.** `InspectFile` returns an error only
when the collector itself is broken — the spool cannot be written, the disk is
full. A bad sector or a permission denial is recorded and the walk continues,
because one unreadable file must never abort a multi-hour acquisition.

## What the harness found

Every one of these was a wrong assumption in the Go implementation that the
unit tests were happy with:

- UAC's artifact files are not valid YAML (bare `%user_home%` scalars, tabs in
  descriptions, unquoted colons in commands) *and* carry inline `# 1GB` comments
  that only work because the value is interpolated into an eval'd shell command,
  where `#` starts a comment.
- `hash_algorithm` defaults to `[md5, sha1]`. Emitting sha256 as well looks
  harmless and makes the output differ from the tool being replaced.
- `enable_find_atime` defaults to **false**, so access times do not participate
  in the date range even though `find` would happily test them.
- An image with no `/etc/passwd` leaves `%user_home%` with nothing to expand to.
  That is a skip, not a failure: UAC iterates an empty user list and never runs
  `find` at all.

## The one intended divergence

`find -nouser` consults the account database of the machine it runs on, so UAC
answers the `user_name_unknown` / `group_name_unknown` artifacts from the
*examiner's* passwd file. On a mounted image that is meaningless: every file
owned by a UID that happens not to exist on the workstation looks orphaned.
uacscan reads the image's own `/etc/passwd` and `/etc/group`, and when the image
has none it declines to answer rather than flagging everything.

The harness knows about this and reports it as EXPECTED rather than a failure
when the tree under test has no account database. UAC's own
`bin/bodyfile2filelists.sh` already does it the correct way with awk, so this
brings the two halves of UAC into agreement.

## Not yet implemented

- **`is_file_list` artifacts** (10 shell-history entries). These are genuinely
  two-phase: the paths come from parsing `HISTFILE=` out of collected rc file
  *contents*, so they are not knowable before the walk.
- **`exclude_file_system`** needs the image's mount table; currently only the
  global path excludes prune.
- **`getcap` and `immutable_files` output format.** The predicates are
  implemented natively (the `security.capability` xattr and the statx immutable
  attribute), but they emit bare paths rather than reproducing `getcap` and
  `lsattr` output, so the harness compares them as path sets rather than bytes.

## License

Apache License 2.0 — see [LICENSE](LICENSE). The same license UAC itself uses,
whose artifact definitions and output formats this project reads and reproduces.

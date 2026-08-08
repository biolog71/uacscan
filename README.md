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

`-o` is a *destination*; each run creates its own directory inside it, named
`uacscan-<hostname>-<os>-<timestamp>` after UAC's own convention. The host name
comes from the image, not the workstation.

No path to a UAC checkout is needed — the artifact definitions are compiled
into the binary. Copy the executable to an examiner workstation and it works.

Key flags: `-m` mount point, `-o` destination directory,
`-output-base-name` to name the run directory yourself, `-s` target operating
system, `-include`/`-exclude` artifact globs, `-start-date-days`/
`-end-date-days` for the date range, `-buffer-limit` for the small-file
threshold, `-version` to see which UAC corpus is baked in. To run against a newer or modified checkout instead of the
embedded copy, pass `-a /path/to/uac/artifacts` (which also switches `uac.conf`
to that checkout's, so definitions and configuration never come from different
places); `-c` overrides the config file on its own.

## Target operating system

Artifacts declare `supported_os`, and that declaration is honoured: a macOS-only
artifact is not compiled for a Linux image. The corpus narrows accordingly.

| Target | Offline rules | | Target | Offline rules |
|---|---|---|---|---|
| linux | 287 | | netbsd | 128 |
| macos | 261 | | openbsd | 128 |
| freebsd | 133 | | solaris | 117 |
| netscaler | 111 | | aix | 104 |
| esxi | 86 | | | |

UAC determines this with `uname -s`, which reports the *examiner's* system — 
correct live, wrong for a mounted image, which is why UAC makes you pass `-s`
offline. uacscan inspects the image instead, looking for marker files
(`etc/os-release`, `System/Library/CoreServices/SystemVersion.plist`,
`bin/freebsd-version`, `etc/release`, and so on), and only falls back to the
host when collecting from `/`. More specific systems win: a NetScaler image is
also a FreeBSD image, and an ESXi image looks Linux-ish.

`-s` overrides detection. Every run prints what it decided and why, because that
decision changes what gets collected:

```
target os     : linux (detected from /mnt/image/etc/os-release)
target os     : macos (specified with -s)
target os     : linux (could not identify the image; assumed the host's -- pass -s to be sure)
```

When the image cannot be identified the filter is disabled rather than applied
blindly — over-collecting beats silently dropping artifacts because a marker
was missing.

## Platforms

Builds for every operating system UAC supports:

| | |
|---|---|
| `darwin` | arm64, amd64 |
| `linux` | amd64, arm64, 386 |
| `freebsd`, `openbsd`, `netbsd` | amd64 |
| `solaris` | amd64 |
| `aix` | ppc64 |

`statx` is Linux-only, so elsewhere `Resolve` falls through to `lstat`. That
costs nothing on Darwin, FreeBSD and NetBSD, which report a birth time directly
from `lstat` — Linux is the odd one out in needing `statx` for the bodyfile's
crtime column. File capabilities (the `getcap` artifact) are a Linux concept and
the xattr read is compiled out elsewhere; `supported_os` means that artifact is
never selected off Linux anyway.

Only Linux/amd64 is *verified* — the differential harness has to run on the
platform under test, so the others are compile-checked but not compared against
UAC.

## Concurrent collections

Several collections can run at once — separate processes, separate images —
and the results are unaffected. Verified rather than assumed: `/usr/share/man`
and `/usr/share/doc` collected concurrently produce bodyfiles byte-identical by
SHA-256 to the same two collected one after the other, and the test suite is
clean under `-race` with four walkers running simultaneously in one process.

Nothing is shared between runs. Every piece of per-scan state — the stat cache,
the content broker, the collector context, the spool store — is constructed per
walk, and the only package-level values are error sentinels, lookup tables and
the read-only embedded corpus.

The one way to break this used to be pointing two runs at the same output
directory. The spool writers append in buffered chunks and a flush boundary
falls mid-line, so two processes writing one bodyfile spliced records from
different images into each other — 19 malformed lines out of 21,912 in a
measured run, with the right total line count and no error reported. Evidence
that is quietly wrong is the worst possible failure for this tool.

That is why each run creates its own directory rather than taking a lock: a
lock can go stale after a kill, whereas `os.Mkdir` simply fails on an existing
directory, so the loser of a race moves to the next name. Two runs starting in
the same second get `...-20260808153140` and `...-20260808153140-2`. The same
command that produced those 19 corrupt lines now produces two clean
directories.

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

A complete UAC tree is embedded for this, so the comparison runs on a machine
that has nothing but this repository — nothing skips, and the version compared
against is always known. That archive is separate from the one the shipped
binary carries: `test/uacfull` holds the whole shell implementation including
`bin/` (8.6 MB of precompiled tools for a dozen architectures), and nothing
outside the harness imports it, so none of it reaches the `uacscan` executable,
which stays at 3.7 MB.

Unlike the definitions archive this one really does unpack onto disk — you
cannot exec a shell script out of an in-memory filesystem — into a temp
directory, once per test binary, with the executable bit preserved.

Both sides of the comparison read the same tree's artifacts, so the two tools
are provably given the same definitions. `TestArtifactsAgreeBetweenTheTwoEmbeddedCopies`
fails if the two archives ever drift apart, since that would quietly make the
comparison say nothing about what the shipped binary collects.

To compare against a working copy instead, set `UAC_ROOT=/path/to/uac` or pass
`-uac`. Regenerate both archives after updating it:

```bash
go generate ./internal/uacdata ./test/uacfull
```

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

## Two intended divergences

Both are cases where UAC consults the examiner's machine while collecting from
an image. The harness knows about each, reports them as EXPECTED rather than
failures, and fails if the difference is anything other than the one described.

**Account lookups.** `find -nouser` consults the account database of the machine
it runs on, so UAC answers the `user_name_unknown` / `group_name_unknown`
artifacts from the *examiner's* passwd file. On a mounted image that is
meaningless: every file owned by a UID that happens not to exist on the
workstation looks orphaned. uacscan reads the image's own `/etc/passwd` and
`/etc/group`, and when the image has none it declines to answer rather than
flagging everything. UAC's own `bin/bodyfile2filelists.sh` already does it this
way with awk, so this brings the two halves of UAC into agreement.

**Command collectors ignore the mount point.** UAC prepends the mount point when
running `find`, but not when running a command collector. Offline, the HISTFILE
lookup therefore greps the examiner's home directories rather than the image's.
It is visible in UAC's own log:

```
CMD grep -E "HISTFILE=.*" "/home/alice"/.bashrc ...
    2> grep: /home/alice/.bashrc: No such file or directory
CMD find /"...\/image"/etc/.login ...          <- the mount point IS applied here
```

Here it merely misses the history files. On a workstation where `/home/alice`
does exist it would be worse than a miss: the examiner's own shell history would
be read and collected into the evidence. uacscan reads the image's rc files, so
it finds history files UAC does not — two of them in the fixture.

## Two-phase artifacts

Ten shell artifacts locate a history file by grepping `HISTFILE=` out of rc
files and feeding the result to a second artifact as a file list. The paths are
not knowable before the walk, so this really is two phases.

The producing half is a `command` collector, which cannot run offline — but the
command is not arbitrary. Across all ten it is the same shape, so it is
recognised and performed natively: rc files are read during the walk, the
assignments extracted, and the resulting paths collected afterwards. That second
phase is not another traversal; the list names specific files, so each is
resolved directly.

A `~/` in a per-user rc file means that user's home, which the path tells you.
In a system-wide rc file the owning user is not implied, so it fans out across
every home. A history file that does not exist is recorded rather than ignored:
it is evidence about configuration. Any command that is *not* the recognised
shape compiles to nothing rather than being approximated.

## Reproducing tool output

Two artifacts pipe `find` output through a command. Both are done natively, and
reproduce the tool's text rather than just listing paths.

`getcap` becomes a read of the `security.capability` attribute, decoded to
libcap's text form. Verified byte-identical to the real `getcap` on this
machine, including a ten-capability binary:

```
/usr/bin/ping cap_net_raw=ep
/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,...,cap_sys_resource=p
```

`immutable_files` becomes `statx` for the immutable attribute — no descriptor —
followed by `FS_IOC_GETFLAGS` only for the few files that have it, rendered in
lsattr's column layout. That layout is not guessable, so it was derived by
measurement: setting individual flags on real files and reading back where
`lsattr` placed each character. `TestFlagStringAgreesWithSystemLsattr` compares
against the installed `lsattr` rather than trusting the table. A different
e2fsprogs release may add columns and shift the tail.

## Handling hostile images

An image is evidence, not input to be trusted. Two places take data that the
image itself controls, and both are contained.

A `HISTFILE` value is a string out of a file's contents. It is normalised
first, so `/` means the *image* root and a leading `..` resolves back inside
rather than climbing out. That alone is not enough — the kernel follows
symlinks in intermediate components, so an image containing `/logs -> /` would
turn `<mount>/logs/etc/shadow` into the examiner's own file — so every
directory leading to the target is checked and a symlinked one is refused. The
copy destination is built from the same string and gets the same containment
check, and output files are created with `O_NOFOLLOW` so a planted symlink
cannot redirect collected evidence elsewhere.

Output failures are separated from evidence failures. A source file that cannot
be read is routine — a bad sector, a permission denial — and is recorded while
the scan continues. A failure to *write* is not: the disk is full, the
destination is unwritable. Those abort the run, because a partial acquisition
that exits zero and looks complete is the worst outcome this tool can have. The
run prints both counts, and the output directory must be empty, so one
collection can never be appended to another.

## Known limits

- **`exclude_file_system` is Linux-only.** It reads `/proc/self/mounts`; other
  platforms return an empty table, so those exclusions cannot be applied there.
  It matters far more live than offline, where a mounted image rarely contains
  pseudo filesystems and the device-boundary check already stops the walk.
- **Only `linux/amd64` is verified.** Everything else is compile-checked; the
  differential harness has to run on the platform under test.
- **Containment is checked, not pinned.** The symlink check on ancestor
  directories is an `lstat` rather than a descent through held descriptors, so
  it is theoretically racy against something mutating the image mid-scan. A
  forensic image is static and should be mounted read-only; `openat2` with
  `RESOLVE_BENEATH` would close the gap on recent Linux at the cost of working
  nowhere else.
- **`command` collectors are out of scope** by design — 661 entries that
  execute on a live system, which no filesystem walk can stand in for. The
  HISTFILE extraction above is the one exception, because it only reads files.

## License

Apache License 2.0 — see [LICENSE](LICENSE). The same license UAC itself uses,
whose artifact definitions and output formats this project reads and reproduces.

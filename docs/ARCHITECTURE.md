# Native Go Forensic Collection Engine (Offline Architecture & Design)

## Executive Summary

This document specifies the architecture for transitioning from **uacscan** (an accelerator and compatibility layer for Unix Artifact Collector / UAC) to a **Pure, Standalone Go Forensic Collection Engine**.

Originally, uacscan was designed to accelerate UAC's offline artifact collection by solving its $O(N \times M)$ traversal bottleneck (490+ artifacts repeatedly invoking `find(1)` over large filesystem images). While uacscan achieved a **14.9× speedup** via a single-pass compiled predicate walk, single-entry stat caching, and decoupled parallel hashing/copying, real-world deployment revealed a fundamental operational and architectural flaw: **fatal `no space left on device` (`ENOSPC`) crashes caused by bulk file copying**.

In production incident response and offline disk triage, attempting to mirror matching files to disk (`cp -r` semantics) indiscriminately copies multi-gigabyte application logs, container layers, cache blobs, core dumps, and system binaries. When the collection destination (such as a triage volume, memory-backed tmpfs, forensics USB, or root partition) runs out of space, write operations fail with `ENOSPC`, triggering [`content.Fatal()`](internal/content/content.go:1) and prematurely aborting the entire collection run. This catastrophic failure drops all in-flight metadata and corrupts the forensic timeline.

Furthermore, uacscan inherited significant technical debt from its strict fidelity to legacy UAC:
1. **Unconstrained Bulk File Copying**: Naive mirroring of raw filesystem trees without storage quotas, dynamic free-space probing, or content bounds, leading directly to `ENOSPC` failures.
2. **Embedded Legacy Corpus**: An embedded 1.5MB tarball ([`internal/uacdata/uac.tar.gz`](internal/uacdata/uac.tar.gz)) and extraction machinery ([`internal/uacdata/uacdata.go:20`](internal/uacdata/uacdata.go:20)).
3. **Fragile Non-Standard Parser**: A custom YAML parser ([`internal/artifact/parse.go:95`](internal/artifact/parse.go:95)) built to handle UAC quirks such as bash-eval comments (`# 1GB`), unquoted colons, raw tabs, and `%user_home%` string interpolations.
4. **Emulation Baggage**: Hardcoded artifact shadowing ([`internal/rules/bodyfilelists.go:108`](internal/rules/bodyfilelists.go:108)), regex parsing of shell command strings ([`internal/rules/histfile.go:44`](internal/rules/histfile.go:44)), and legacy shell configuration ([`internal/config/config.go:78`](internal/config/config.go:78)).
5. **Coupled Test Harness**: Verification tightly coupled to executing UAC's shell scripts on Linux hosts ([`test/harness/main.go:1`](test/harness/main.go:1), [`test/uacfull/uacfull.go:1`](test/uacfull/uacfull.go:1)).

The target architecture discards legacy file-copying paradigms and UAC emulation baggage, establishing an independent, high-performance, forensically sound collection engine implemented natively in Go. **Phase 1** shifts fundamentally to **Zero-Copy Forensic Triage & Targeted Artefact Extraction**:
- **Zero-Copy Metadata by Default**: The primary engine operation extracts complete timelines (`stat` / SleuthKit `mactime` 3.x), path inventories and security attributes (`find`), and cryptographic digests (`hash`) without duplicating raw files.
- **Targeted Artefact Extraction**: Replaces bulk file copying with surgical, bounded evidence extraction (`artefact` collector): capturing small configuration files, shell histories, scheduled jobs, and windowed log slices (head/tail sampling), streamed directly into structured JSON Lines or compressed archives.
- **Proactive Storage Governance & Circuit Breakers**: Continuous destination filesystem space probing via `statvfs(2)` / `syscall.Statfs`, strict collection byte quotas, and non-fatal degradation guarantees: low disk space gracefully halts content extraction while metadata collection continues uninterrupted, guaranteeing that an `ENOSPC` condition never aborts a forensic scan.

---

## Strategic Review: Current Architecture vs. Pure Go Vision

| Architectural Dimension | Current Architecture (`uacscan`) | Target Pure Go Architecture |
|---|---|---|
| **Primary Identity** | Drop-in accelerator & emulator for UAC | Standalone, native Go forensic collection engine |
| **Evidence Acquisition Strategy** | Unbounded bulk file mirroring (`file` collector copying raw trees to disk) | **Zero-Copy Forensic Triage & Targeted Artefact Extraction**: Collects metadata, timelines, hashes, and surgical bounded artifacts; raw bulk file duplication is eliminated |
| **Storage Safety & Quota Control** | None; write errors trigger fatal abort on `ENOSPC` | **Proactive Storage Governance**: Continuous `statvfs` free-space monitoring, hard collection byte budgets, and non-fatal circuit breakers that degrade to metadata-only collection without aborting |
| **Artifact Catalog** | 490+ legacy UAC YAML files embedded as `tar.gz` ([`internal/uacdata/uac.tar.gz`](internal/uacdata/uac.tar.gz)) | Standard native YAML catalog embedded via `//go:embed` with strict Go struct validation (no bash eval comments, no string substitution hacks) |
| **Parser Robustness** | Hand-rolled relaxed parser ([`internal/artifact/parse.go:95`](internal/artifact/parse.go:95)) supporting shell-eval comments and unquoted values | Strict standard YAML parser (`gopkg.in/yaml.v3`) with compile-time schema validation and zero shell-eval workarounds |
| **User/Home Discovery** | Magic `%user_home%` string replacement ([`internal/rules/rules.go:1`](internal/rules/rules.go:1)) and regex heuristics | Dual resolution: mount-relative `/etc/passwd` ([`internal/passwd/passwd.go:1`](internal/passwd/passwd.go:1)) + disk directory enumeration (`<mount>/home/*`, `<mount>/root`, `<mount>/Users/*`) for LDAP/AD/SSO PAM VM snapshots, pinned via [`fsref.ResolveBeneath()`](internal/fsref/beneath.go:1) |
| **Target OS Resolution** | Heuristic `/etc/os-release` parsing across image mount | Mandatory `--target-os` flag for external mount points / VM snapshots, eliminating ambiguity for detached subvolumes (standalone `/home`, `/var`, `/opt` EBS snapshots) |
| **Forensic Output Architecture** | UAC-specific text lists, bodyfile, and uncompressed raw file mirrors | Primary streaming JSON Lines (`.jsonl`), SleuthKit `mactime` 3.x bodyfile, inline small artefact records, and compressed artefact spools |
| **Filesystem Boundaries & Node Safety** | Global cross-device boolean flag, potential hangs on FIFO/devices | Smart boundary traversal auto-pruning virtual filesystems (`proc`, `sysfs`, `devpts`) while traversing same-disk subvolumes (btrfs, ZFS, APFS, LVM); strict node safety scanning special files via `statx`/`lstat` only without opening |
| **Two-Phase Artifacts** | Ad-hoc regex parsing of shell pipes (`grep HISTFILE=`) ([`internal/rules/histfile.go:44`](internal/rules/histfile.go:44)) | Structured multi-stage collector pipeline with explicit dependency graph |
| **Shadowing & Precedence**| Hardcoded `bodyfile2filelists` rule rewrite ([`internal/rules/bodyfilelists.go:108`](internal/rules/bodyfilelists.go:108)) | Clean rule activation profiles and target artifact filtering |
| **Configuration** | Legacy key-value `uac.conf` format ([`internal/config/config.go:78`](internal/config/config.go:78)) | Structured, versioned YAML configuration file with storage quota & circuit-breaker limits |
| **Test Strategy** | Differential comparisons against shell-based UAC runs ([`test/harness/main.go:1`](test/harness/main.go:1)) | Standalone Go unit, synthetic filesystem fixtures, ENOSPC simulation tests, and golden-file regression tests |

### Technical Debt in Current Codebase

1. **Unbounded Raw File Mirroring ([`collector/collectors.go:346`](collector/collectors.go:346))**
   - The legacy `fileCollector` attempts to recreate the entire directory tree of matching files under `[root]/...` in the destination directory.
   - When encountering large logs or disks with limited destination capacity, writes fail with `ENOSPC`.
   - Write errors are wrapped as [`content.Fatal()`](internal/content/content.go:1), crashing the traversal and losing already collected forensic metadata.
2. **Embedded Tarball Dependency ([`internal/uacdata/`](internal/uacdata/))**
   - Requires code-generation tooling ([`internal/uacdata/gen/main.go:1`](internal/uacdata/gen/main.go:1)) to refresh embedded archives.
   - Tied to third-party upstream UAC release cycles and bugs.
3. **Bespoke Artifact Parser Quirks ([`internal/artifact/parse.go`](internal/artifact/parse.go:1))**
   - Contains custom methods like [`splitKeyValue()`](internal/artifact/parse.go:172), [`stripComment()`](internal/artifact/parse.go:193), and [`shellSplit()`](internal/artifact/parse.go:313) specifically to imitate shell `eval` behavior.
   - Lacks compile-time safety or formal schema validation.
4. **Coupled Two-Phase Shell Logic ([`internal/rules/histfile.go`](internal/rules/histfile.go:1) & [`internal/rules/bodyfilelists.go`](internal/rules/bodyfilelists.go:1))**
   - [`ParseHistfileCommand()`](internal/rules/histfile.go:44) inspects strings like `grep -h -s -E '^HISTFILE=' ... | sed ...` to detect history collection.
   - [`ApplyBodyfileListsShadowing()`](internal/rules/bodyfilelists.go:108) hardcodes logic to drop 12 specific UAC artifacts when `bodyfile2filelists.yaml` is active.
5. **Shell Configuration Artifacts ([`internal/config/config.go`](internal/config/config.go:1))**
   - Parses shell variable assignments (`var='val'`) from `uac.conf`.
   - Constrained by UAC's configuration semantics.

---

## Pure Go Architecture (Phase 1: Offline Engine)

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CLI / Entry Point                               │
│                       cmd/forensic-scan/main.go                        │
│                (Flag parsing, config loading, logging)                 │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         Engine Coordinator                             │
│                             pkg/engine                                 │
│                   func (e *Engine) Run(ctx, Opts)                      │
└───────┬───────────────────────────┬────────────────────────────┬───────┘
        │                           │                            │
        ▼                           ▼                            ▼
┌───────────────┐           ┌───────────────┐           ┌────────────────┐
│ Rule Catalog  │           │ Target Image  │           │ Output Spool   │
│ & Profiles    │           │ Environment   │           │ Manager        │
│ (Native YAML/ │           │ (OS detect,   │           │ (Disk spools,  │
│ Go structs)   │           │ mounts, pass) │           │ safe manifest) │
└───────┬───────┘           └───────┬───────┘           └────────┬───────┘
        │                           │                            │
        │                           │             ┌──────────────┴───────┐
        │                           │             │ Space Guard          │
        │                           │             │ & Circuit Breaker    │
        │                           │             │ (Continuous statfs   │
        │                           │             │  & quota manager)    │
        │                           │             └──────────────┬───────┘
        │                           │                            │
        └───────────────────────────┼────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Compiled Execution Plan                         │
│                         pkg/engine/planner.go                          │
│               - Anchor directories & traversal roots                   │
│               - Compiled path & attribute predicates                   │
│               - Collector instance registry                            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Single-Pass Filesystem Walker                      │
│                           internal/walk/walk.go                        │
│             - Hostile symlink containment (RESOLVE_BENEATH)            │
│             - Subtree pruning (MayContainMatches / ShouldSkipDir)      │
│             - Single-entry Stat Cache (fsref.Resolve -> statx/lstat)   │
└───────┬───────────────────────────┬────────────────────────────┬───────┘
        │                           │                            │
        ▼                           ▼                            ▼
┌───────────────┐           ┌───────────────┐           ┌────────────────┐
│ Bodyfile/Stat │           │ Inventory/Find│           │ Content Broker │
│ Collector     │           │ Collector     │           │ (Parallel Pool)│
│ (Mactime 3.x) │           │ (Path Lists)  │           │                │
└───────────────┘           └───────────────┘           └────────┬───────┘
                                                                 │
                                    ┌────────────────────────────┴───────┐
                                    ▼                                    ▼
                             ┌───────────────┐                   ┌───────────────┐
                             │ Digest Worker │                   │ Artefact      │
                             │ (Parallel     │                   │ Extractor     │
                             │  multi-hash)  │                   │ (Surgical,    │
                             │               │                   │  bounded caps,│
                             │               │                   │  windowing)   │
                             └───────┬───────┘                   └───────┬───────┘
                                     │                                   │
                                     └─────────────────┬─────────────────┘
                                                       ▼
                                        ┌────────────────────────────────┐
                                        │ Deterministic Sequencer        │
                                        │ (Walk-order output streaming)  │
                                        └────────────────┬───────────────┘
                                                         ▼
                                        ┌────────────────────────────────┐
                                        │ Spool Store & Manifest         │
                                        │ (JSONL / Compressed streams)   │
                                        └────────────────────────────────┘
```

---

## Native Artifact & Rule Specification Model

In the pure Go architecture, artifact definitions become **schema-validated, declarative specifications**.

### 1. Embedded Artifact Catalog & Specification Schema (`pkg/artifact`)

The artifact catalog transitions entirely away from embedded `.tar.gz` archives and ad-hoc shell evaluation. The catalog consists of native YAML files embedded directly into the Go binary using `//go:embed rules/*.yaml`. Every rule is strictly validated against Go structs:
- **Zero Shell Hacks**: Eliminates all bash-eval inline comments (`# 1GB`), unquoted values, raw tab escapes, and `%user_home%` string substitution heuristics.
- **Strict Go Struct Validation**: Deserialized via `gopkg.in/yaml.v3` with known-field validation, strict type enforcement, and compile-time test verification.
- **Elimination of Naive Bulk File Copying**: Replaces the legacy unbounded `file` collector with the targeted `artefact` collector. Rather than copying entire raw files to disk, the `artefact` collector defines surgical bounded extraction parameters (max bytes, windowing, log head/tail) with storage quota protection.
- **Forward-Compatibility Note**: Phase 1 is scoped strictly to POSIX targets (Linux, macOS, FreeBSD). The `SupportedOS` field and `ScopeCriteria.Paths` are kept as plain strings (not POSIX-only types) specifically so that a future phase can add `windows` as a `SupportedOS` value and Windows-specific `ScopeCriteria` fields (e.g. registry hives, MFT, volume shadow copies) without a breaking schema change. No Windows-specific behavior is implemented in Phase 1; this is a naming/typing constraint only, verified by a schema unit test that rejects any Phase 1 code path from assuming POSIX-only path semantics (e.g. `/`-only separators) inside the schema package itself.

```go
package artifact

import "time"

// Profile groups artifacts into collection targets (e.g. "triage", "full", "offline-fast").
type Profile struct {
    Name        string   `yaml:"name" json:"name"`
    Description string   `yaml:"description" json:"description"`
    Artifacts   []string `yaml:"artifacts" json:"artifacts"`
}

// Definition specifies a single collection rule.
type Definition struct {
    ID          string             `yaml:"id" json:"id"`
    Description string             `yaml:"description" json:"description"`
    Author      string             `yaml:"author,omitempty" json:"author,omitempty"`
    SupportedOS []string           `yaml:"supported_os" json:"supported_os"` // linux, darwin, freebsd, etc.
    Collector   CollectorType      `yaml:"collector" json:"collector"`       // stat, find, hash, artefact
    Scope       ScopeCriteria      `yaml:"scope" json:"scope"`
    Filter      FilterCriteria     `yaml:"filter" json:"filter"`
    Extraction  *ExtractionConfig  `yaml:"extraction,omitempty" json:"extraction,omitempty"`
    Output      OutputConfig       `yaml:"output" json:"output"`
}

type CollectorType string

const (
    CollectorStat     CollectorType = "stat"     // Bodyfile / metadata timeline
    CollectorFind     CollectorType = "find"     // Path listings & attribute discovery
    CollectorHash     CollectorType = "hash"     // Cryptographic digests
    CollectorArtefact CollectorType = "artefact" // Targeted forensic artefact extraction (bounded)
)

type ScopeCriteria struct {
    Paths        []string `yaml:"paths" json:"paths"`                 // e.g. ["/etc", "/var/log", "{USER_HOMES}"]
    ExcludePaths []string `yaml:"exclude_paths,omitempty" json:"exclude_paths,omitempty"`
    MaxDepth     int      `yaml:"max_depth,omitempty" json:"max_depth,omitempty"`
    CrossDevice  bool     `yaml:"cross_device,omitempty" json:"cross_device,omitempty"`
}

type FilterCriteria struct {
    NamePatterns    []string       `yaml:"name_patterns,omitempty" json:"name_patterns,omitempty"`
    PathPatterns    []string       `yaml:"path_patterns,omitempty" json:"path_patterns,omitempty"`
    FileTypes       []string       `yaml:"file_types,omitempty" json:"file_types,omitempty"` // f, d, l, s, p, b, c
    Permissions     []string       `yaml:"permissions,omitempty" json:"permissions,omitempty"`
    MinSize         *int64         `yaml:"min_size,omitempty" json:"min_size,omitempty"`
    MaxSize         *int64         `yaml:"max_size,omitempty" json:"max_size,omitempty"`
    ModifiedWithin  *time.Duration `yaml:"modified_within,omitempty" json:"modified_within,omitempty"`
    ChangedWithin   *time.Duration `yaml:"changed_within,omitempty" json:"changed_within,omitempty"`
    AccessedWithin  *time.Duration `yaml:"accessed_within,omitempty" json:"accessed_within,omitempty"`
    NoUser          bool           `yaml:"no_user,omitempty" json:"no_user,omitempty"`
    NoGroup         bool           `yaml:"no_group,omitempty" json:"no_group,omitempty"`
}

// ExtractionConfig dictates how relevant content is extracted without unbounded file copying.
type ExtractionConfig struct {
    MaxBytes       int64          `yaml:"max_bytes,omitempty" json:"max_bytes,omitempty"`             // Max bytes captured per file (default: 5MB)
    WindowStrategy WindowStrategy `yaml:"window_strategy,omitempty" json:"window_strategy,omitempty"` // full, tail, head
    WindowLines    int            `yaml:"window_lines,omitempty" json:"window_lines,omitempty"`       // For log files: e.g. last 5000 lines
    InlineInRecord bool           `yaml:"inline_in_record,omitempty" json:"inline_in_record,omitempty"` // Emit directly inside stream/records.jsonl
    Deduplicate    bool           `yaml:"deduplicate,omitempty" json:"deduplicate,omitempty"`         // Deduplicate payload across hardlinks/identical hashes
}

type WindowStrategy string

const (
    WindowFull WindowStrategy = "full" // Bounded to MaxBytes
    WindowTail WindowStrategy = "tail" // Slices the last N lines or bytes (ideal for active logs)
    WindowHead WindowStrategy = "head" // Slices the first N lines or bytes
)

type OutputConfig struct {
    FileName   string   `yaml:"file_name" json:"file_name"`     // Destination file in spool/output
    Algorithms []string `yaml:"algorithms,omitempty" json:"algorithms,omitempty"` // For hash: md5, sha1, sha256
    Compress   bool     `yaml:"compress,omitempty" json:"compress,omitempty"`
}
```

### 2. User Home Discovery & VM Snapshot Scoping

User artifact scoping abandons string substitution in favor of robust **Dual Resolution** designed specifically for real-world enterprise VM snapshots, with an **anchor-based** rule model that prevents rule-count explosion on systems with large user populations.

1. **Dual Resolution Strategy**:
   - **Mount-Relative `/etc/passwd` Parsing**: Parsed via [`internal/passwd/passwd.go:1`](internal/passwd/passwd.go:1) to identify *every distinct home path* declared for local accounts — not just `/home/*`, but also `/root`, `/var/root` (macOS), and any non-standard home directory a service account may declare (e.g. `/var/lib/postgresql`, `/opt/oracle`, `/srv/www`, `/var/www`). Attackers and legitimate daemons alike frequently run under system accounts whose home is outside `/home`; skipping them creates a forensic blind spot.
   - **Disk Directory Enumeration**: Systematically enumerates standard home parent directories on disk: `<mount>/home/*`, `<mount>/Users/*` (macOS), and `<mount>/var/home/*` (immutable distros such as Fedora Silverblue/CoreOS, where `/home` is a symlink to `/var/home`).
   - **Enterprise & Domain-Joined VM Snapshot Support**: In production cloud environments, VMs often authenticate against centralized directory services (Active Directory, LDAP, FreeIPA, Okta PAM / SSSD). On detached forensic disks or offline snapshots, remote directory servers are unreachable and network PAM caches may be cold or absent from `/etc/passwd`. Enumerating directory trees guarantees roaming and domain profiles are captured, even when the account record itself is missing.
   - **Orphan Directory Provenance**: A home directory discovered by disk enumeration with no matching `/etc/passwd` entry is tagged `account_source: "unindexed_directory"` in every emitted record (see [Forensic Output Architecture](#1-forensic-output-architecture)), so analysts can distinguish confirmed local accounts from orphaned/domain-joined profiles without losing the evidence.

2. **Anchor-Based Rule Registration (Rule-Explosion Prevention)**:
   - **Problem**: Multi-tenant servers, universities, and jump boxes can have `/home` populations in the tens of thousands. Naively expanding every user-scoped artifact (e.g. `.bash_history`, `.ssh/authorized_keys`, browser profiles — commonly 50+ definitions) into a fully materialized [`rules.Rule`](internal/rules/rules.go:1) per discovered home would produce >100,000 compiled rules before the walk even starts, degrading both startup latency and the per-file predicate evaluation cost that the single-pass design depends on.
   - **Solution**: User-scoped artifacts are **not** expanded per-home at compile time. Instead:
     - Every distinct home path resolved by Dual Resolution (from `/etc/passwd` *and* disk enumeration) is registered once as a lightweight **anchor** (`anchors.HomeAnchor{Root, AccountSource}`) in a dedicated anchor index, independent of the general rule set.
     - User-scoped `Definition`s carry **relative path templates** (e.g. `.ssh/authorized_keys`, `.bash_history`) rather than pre-expanded absolute paths.
     - The walker's existing subtree-pruning check ([`rules.MayContainMatches`](internal/rules/rules.go:590)) is extended with an O(1) anchor lookup: when the walker enters a directory matching a registered anchor root, it binds the anchor's relative templates into a small number of active predicates *scoped to that subtree only*, and unbinds them on exit.
     - Total live rule count stays bounded by `(number of user-scoped definitions) × (anchors currently on the active traversal path)` — typically a handful — instead of `(definitions) × (total homes on disk)`.
   - **Trade-off**: Anchor binding adds a small amount of bookkeeping at each directory boundary, but this is O(depth) and negligible next to the O(files) savings; it also naturally generalizes to the non-`/home` service-account homes identified above.

3. **Strict Containment via [`fsref.ResolveBeneath()`](internal/fsref/beneath.go:1)**:
   - Untrusted snapshots may contain adversarial symlinks planted within user home locations (e.g. `/home/attacker -> /etc` or symlinks targeting the host runner).
   - Every candidate anchor root is strictly pinned and validated using [`fsref.ResolveBeneath()`](internal/fsref/beneath.go:1) prior to being registered. Any path escaping the designated mount root is rejected and logged as a containment violation, not silently skipped.

### 3. Target OS Determination on External Mounts

When acquiring live systems, the running kernel OS is known. However, forensic analysis typically inspects offline VM snapshots, EBS volumes, or detached disk images:
- **Mandatory `--target-os` on External Mounts**: When `--mount` points to an external directory (anything other than root `/`), specifying `--target-os <linux|darwin|freebsd>` is **mandatory**.
- **Detached Subvolume Disambiguation**: Eliminates reliance on heuristic detection. Detached volumes (such as standalone `/home`, `/var`, `/opt`, or database EBS snapshots) frequently lack root filesystems, `/etc/os-release`, `/etc/issue`, or `/System/Library/CoreServices`. Requiring `--target-os` guarantees unambiguous rule selection across all subvolumes.

---

## Core Engine Innovations (Retained & Refined)

The pure Go architecture retains the high-performance architectural patterns that provide uacscan its performance advantage:

### 1. Single-Pass Walker & Pruning Subsystem ([`internal/walk/walk.go`](internal/walk/walk.go:1))
- **Single Traversal**: Traverses the mount point once from root to leaf, evaluating all compiled rules against each visited node.
- **Subtree Pruning ([`rules.MayContainMatches`](internal/rules/rules.go:1))**: Before descending into subdirectories, the walker checks prefix anchors and path globs across all active rules. If no rule is interested in a subtree, the directory is pruned without inspecting its children.

### 2. Zero-Redundancy Stat/Statx Caching ([`internal/fsref/fsref.go`](internal/fsref/fsref.go:1))
- **`fsref.Resolve()` & `statx`**: Employs Linux `statx(2)` to obtain birth time (`btime`), inode change time (`ctime`), permissions, attributes, and file sizes in a single syscall without auxiliary `ioctl` flags.
- **Single-Entry Cache ([`fsref.Cache`](internal/fsref/fsref.go:210))**: Walker sets the cache once per visited file. All active collectors (`stat`, `find`, `hash`, `file`) read metadata from the cache via `ctx.FileRef(path)` without issuing repeated kernel calls.

### 3. Decoupled Parallel Content Broker ([`internal/content/content.go`](internal/content/content.go:1))
- **Metadata / Content Decoupling**: Metadata evaluation remains single-threaded for deterministic directory traversal and minimal lock contention.
- **Worker Pool**: Files requiring content inspection (hashing or copying) are dispatched to a worker pool (`runtime.NumCPU()` workers).
- **Independent Content Handle**: Consumers access file content via `content.Content` with offset-independent `ReadAt(buf, off)` and pooled buffers, preventing shared file pointer bugs.
- **Deterministic Walk-Order Sequencer**: As workers complete out-of-order digest and copy jobs, the sequencer collects and reorders their results to strictly match the filesystem walk order, guaranteeing deterministic, reproducible output.

### 4. Robust Disk Spooling & Inline Artefact Streaming ([`internal/spool/spool.go`](internal/spool/spool.go:1))
- **Memory-Bounded Buffering**: Results stream directly to disk spools with chunked write buffers (`bufio.Writer`). Spool files never materialize multi-gigabyte collections in memory.
- **Inline Small Artefact Streaming**: Rather than creating thousands of small files on the destination filesystem (which exhausts disk inodes and causes directory thrashing), small extracted artifacts (<64KB, e.g. `/etc/passwd`, `/etc/hosts`, `.bash_history`) are encoded and embedded directly into `stream/records.jsonl`.
- **Single-Stream Compressed Spools**: Larger extracted artifacts are written to a single append-only compressed archive (`artefacts/artefacts.tar.zst` or `.tar.gz`) instead of an uncompressed mirrored filesystem tree.
- **Control Byte Escaping ([`spool.Writer.WriteLine`](internal/spool/spool.go:61))**: Non-printable characters, newlines, and tabs in filenames are sanitized to prevent log injection or formatting attacks.
- **Atomic Run Directory ([`internal/outdir/outdir.go:37`](internal/outdir/outdir.go:37))**: Creates unique collection directories using `os.Mkdir` to avoid collision with concurrent or interrupted runs.

### 5. Proactive Space Governance & ENOSPC Circuit Breaker
- **Continuous Free-Space Probing & Atomic Byte Reservations**:
  - Queries destination filesystem capacity via `statvfs(2)` / `syscall.Statfs` prior to traversal.
  - **TOCTOU Race Prevention**: To prevent Time-of-Check to Time-of-Use races across concurrent worker routines, workers must acquire an atomic byte reservation from an in-memory token bucket before initiating extraction (`min(file.Size, MaxArtefactBytes)`).
  - If in-flight reservations plus safety margins exceed destination available space or the global `--max-collection-bytes` ceiling, content extraction is rejected immediately before performing any disk I/O.
- **Resilient ENOSPC Handling**:
  - In the event of external disk pressure causing an unexpected `syscall.ENOSPC` during an active write, the engine intercepts the error rather than wrapping it with [`content.Fatal()`](internal/content/content.go:1).
  - The circuit breaker trips immediately, in-flight content writes are gracefully aborted and cleaned up, a non-fatal anomaly is recorded in `manifest.json`, and metadata collection continues uninterrupted.
- **Configurable Global Storage Quotas**: Enforces a strict total bytes ceiling on extracted artefact content (`--max-collection-bytes`, e.g. 1GB).
- **Non-Fatal Graceful Degradation (Circuit Breaker)**:
  - If available disk space on the destination volume drops below a configurable safety margin (`--min-free-space`, default 500MB or 10%), or if the total extracted content exceeds `--max-collection-bytes`, the engine immediately trips its internal storage circuit breaker.
  - Artefact content extraction is cleanly paused, and a warning event is recorded in `manifest.json` and `stream/records.jsonl` (`"status": "degraded_space_limit_reached"`).
  - Crucially, zero-byte-cost metadata collection (`stat` / bodyfile, `find` / path listings, and `hash` digests) **continues to run to completion**. The scan never fails with an unhandled fatal `ENOSPC` error, preserving the forensic timeline intact.

### 6. Hostile Image Containment ([`internal/fsref/beneath.go`](internal/fsref/beneath.go:1))
- **Symlink Jail**: Uses Linux `openat2` with `RESOLVE_BENEATH` where supported, preventing symlinks from escaping the forensic mount into the host filesystem.
- **Safe Fallback**: On platforms without `RESOLVE_BENEATH`, verifies every path component via `lstat` traversal.
- **Root-Pinned User Homes**: All discovered home roots (`/home/*`, `/Users/*`, `/root`) are pinned and validated through [`fsref.ResolveBeneath()`](internal/fsref/beneath.go:1) to prevent crafted symlinks from tricking the scanner into traversing outside the target image.

### 6. Filesystem Boundaries & Special Node Safety
- **Smart Boundary Traversal**:
  - Automatically identifies and prunes pseudo- and virtual filesystems (`proc`, `sysfs`, `devpts`, `devtmpfs`, `cgroup`) via mount table analysis.
  - Unlike naive POSIX `st_dev` boundary checks that abort upon crossing subvolume mount boundaries, the engine tracks storage roots to permit traversing same-disk subvolumes (btrfs subvolumes, ZFS datasets, APFS volume groups, and LVM thin pools) without missing legitimate artifact paths.
- **Strict Node Safety**:
  - Special files (character and block devices, FIFOs/named pipes, and Unix domain sockets) are scanned **strictly for metadata** via `statx`/`lstat`.
  - Non-regular files are **never opened** for content hashing or copying (`O_NONBLOCK` or ordinary `open`). This guarantees zero hangs on unbacked FIFOs and prevents accidental hardware or device driver activation when scanning mounted host images.

---

## Phase 1: Offline Collector Specifications & Forensic Output Architecture

Phase 1 implements four offline collectors natively in Go without external dependencies, centered around a modern forensic streaming architecture:

```
Collector Type │ Primary Output Format            │ Optional Legacy Format            │ Forensic Description
───────────────┼──────────────────────────────────┼───────────────────────────────────┼──────────────────────────────────────────────────────────
stat           │ bodyfile/bodyfile.txt            │ bodyfile/bodyfile.txt             │ Sleuth Kit mactime 3.x format:
               │                                  │                                   │ MD5|path|inode|mode_str|uid|gid|size|atime|mtime|ctime|crtime
all (stream)   │ stream/records.jsonl             │ -                                 │ Structured JSON Lines: timestamp, inode, metadata, hashes, artifact ID, errors
find           │ stream/records.jsonl             │ lists/<artifact_id>.txt           │ Matched paths, file attributes, orphan ownership flags
hash           │ stream/records.jsonl             │ hashes/<algorithm>_<id>.txt       │ Cryptographic digests (SHA-256, SHA-1, MD5)
artefact       │ stream/records.jsonl (inline) or │ artefacts/<id>/<path>             │ Targeted forensic extraction: surgical configs, histories,
               │ artefacts/artefacts.tar.zst      │                                   │ windowed log slices (strictly bounded; zero whole-file mirrors)
```

### 1. Forensic Output Architecture

1. **Primary Output: Streaming Structured JSON Lines (`.jsonl`)**:
   - The engine streams events to disk in append-only JSON Lines format (`stream/records.jsonl`), eliminating memory bloat.
   - Each JSON record is self-contained and carries forensic metadata, hashes, and optional inline artefact content:
     ```json
     {
       "timestamp": 1710000000,
       "path": "/etc/shadow",
       "inode": 131205,
       "mode": "-rw-r-----",
       "uid": 0,
       "gid": 42,
       "size": 1142,
       "artifact_id": "linux_auth_shadow",
       "hashes": {
         "sha256": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
         "md5": "4d186321c1a7f0f354b297e8914ab240"
       },
       "account_source": "passwd_entry",
       "artefact": {
         "extracted": true,
         "strategy": "full",
         "size_bytes": 1142,
         "inline_content": "root:$6$rounds=656000$...",
         "truncated": false
       },
       "error": null
     }
     ```
   - **`account_source` Field**: Present on any record produced under a resolved user-home anchor (see [User Home Discovery](#2-user-home-discovery--vm-snapshot-scoping)). Values: `"passwd_entry"` (account confirmed in `/etc/passwd`) or `"unindexed_directory"` (home discovered only via disk enumeration, e.g. an orphaned or domain-joined profile with no local account record). This lets analysts immediately triage evidence from accounts that shouldn't exist locally.
   - **`artefact` Block**: Contains metadata about the extracted payload. Small textual artefacts (<64KB) are embedded directly via `inline_content` (or base64 for binary fragments), completely eliminating file-per-artifact filesystem explosion and avoiding inode exhaustion on destination storage.
   - Standardizes downstream analysis for SIEM, timeline visualizers, and cloud ingestion pipelines without custom text parsing.
2. **Timeline Output: SleuthKit `mactime` 3.x Bodyfile**:
   - Maintains full compatibility with standard timeline forensic tools (`mactime`, Plaso).
   - Generated directly by the `stat` collector at [`collector/collectors.go:36`](collector/collectors.go:36) via zero-allocation string formatting to `bodyfile/bodyfile.txt`.
3. **Compatibility Mode: Optional Flat Text Lists (`--format=legacy-text`)**:
   - When specified via `--format=legacy-text`, the engine produces flat newline-delimited path listings in `lists/<artifact_id>.txt` and classic `hashes/<algorithm>_<id>.txt` checksum manifests for compatibility with legacy post-processing scripts.

### 2. `stat` Collector (Timeline / Bodyfile)
- **Specification**: Emits lines in standard Sleuth Kit `mactime` 3.x format:
  ```text
  0|/etc/passwd|131204|drwxr-xr-x|0|0|2412|1710000000|1710000000|1710000000|1710000000
  ```
- **Fidelity**:
  - `mode`: Decoded into standard 10-character mode string (`-rw-r--r--`, `drwxr-xr-x`) via [`fsref.ModeString()`](internal/fsref/fsref.go:145).
  - Timestamps: atime, mtime, ctime, and crtime (birth time) rendered as Unix epoch seconds.
  - Zero-allocation line rendering directly to spool buffer.

### 3. `find` Collector (Inventory & Filtering)
- **Specification**: Evaluates paths against defined attribute and name filters, emitting matches to the streaming record log (or `lists/<id>.txt` in legacy text mode).
- **Features**:
  - Name and path glob matching with negative patterns (`exclude_patterns`).
  - Owner resolution: Discovers orphan files (`-nouser`, `-nogroup`) by parsing the image's `/etc/passwd` and `/etc/group` via [`internal/passwd/passwd.go`](internal/passwd/passwd.go:1).
  - File attributes: SUID, SGID, immutable flags, and Linux file capabilities (`xattr` `security.capability` via [`internal/fileattr/capability.go`](internal/fileattr/capability.go:1)).

### 4. `hash` Collector (High-Throughput Cryptographic Digests)
- **Specification**: Calculates cryptographic digests (SHA-256, SHA-1, MD5) for matched files.
- **Chunk-Based Fan-Out ([`collector/collectors.go:279`](collector/collectors.go:279))**:
  - Rather than serializing digests with `io.MultiWriter`, reads 64KB chunks and fans them out to active hashing algorithms concurrently across cores.
  - **Strict Node Safety**: Non-regular files (character/block devices, FIFOs, sockets) are bypassed entirely.

### 5. `artefact` Collector (Targeted Forensic Artefact Extraction)
- **Elimination of Raw File Mirroring**: The pure Go engine explicitly rejects copying raw filesystem trees to disk (`cp -r` / legacy `file` collector). Instead, the `artefact` collector selectively extracts high-value forensic evidence:
  - System configuration files (`/etc/passwd`, `/etc/pam.d/*`, `/etc/sudoers`, `/etc/hosts`, SSH authorized keys).
  - User activity and session history (`.bash_history`, `.zsh_history`, `.bashrc`, login scripts).
  - Scheduled tasks and autoruns (`/etc/cron*`, `/etc/systemd/system/*`, `/var/spool/cron/*`).
- **Log Windowing & Slicing**: Rather than copying 10GB–50GB rotating active logs (e.g. `/var/log/syslog`, `/var/log/messages`), the collector performs **windowed extraction** (capturing the tail $N$ lines, e.g., the last 5,000 lines or 5MB) while hashing the complete file via the `hash` collector.
- **Zero-Copy Triage Mode (`--metadata-only` / `--no-content`)**:
  - When invoked with `--metadata-only`, content extraction is disabled entirely. The engine produces complete timelines (`bodyfile.txt`), path inventories, and cryptographic digests without writing any file content, guaranteeing lightning-fast triage with zero risk of filling the destination drive.
- **Proactive Storage Quota & Circuit Breaker**:
  - Every candidate artefact must pass the **Space Guard** check: if destination free space drops below `--min-free-space` (default 500MB) or if total content bytes exceed `--max-collection-bytes` (default 1GB), the circuit breaker halts further content extraction.
  - Files exceeding `--max-artefact-bytes` (default 5MB) are recorded with their metadata and cryptographic digests, but their raw bodies are skipped and flagged with `"truncated": true, "reason": "exceeds_max_artefact_bytes"` in `stream/records.jsonl`.
  - Content writes that fail never panic or return fatal errors; they are isolated and logged as non-fatal forensic warnings.

### 6. Multi-Stage Pipeline (Replacing Two-Phase Shell Logic)
In place of regex-parsing shell scripts to discover history files ([`internal/rules/histfile.go:44`](internal/rules/histfile.go:44)), Phase 1 introduces a native **Multi-Stage Pipeline** with defense-in-depth against hostile or evasive dynamic targets:

- **Stage 1 (Primary Walk)**: Traverses the filesystem, collecting metadata and identifying configuration files (e.g., shell profiles, environment definitions).
- **Stage 2 (Dynamic Expansion)**: Inspects identified files using structured Go parsers (e.g., parsing `HISTFILE` shell assignments natively without regex guessing) and emits *candidate* secondary targets. Values containing unresolved shell parameter expansion (e.g. `$HOME`, `${USER}`) are resolved only against variables already known from the current anchor context (the owning account's home and username); assignments that reference runtime-only state are recorded as `unresolved` in the manifest rather than guessed at.
- **Stage 3 (Targeted Fetch)**: Every candidate path emitted by Stage 2 is treated as **untrusted input**, since it originates from evidence content, not from the trusted artifact catalog. Before any read is attempted:
  1. **Path Containment**: The candidate path is normalized and resolved through [`fsref.ResolveBeneath()`](internal/fsref/beneath.go:44) relative to the mount root, exactly as user-home anchors are. Paths that resolve outside the mount (e.g. `HISTFILE=../../../../etc/shadow`, or a symlink planted to escape containment) are rejected and logged as a containment violation, not silently skipped.
  2. **Strict Non-Regular File Gating**: The resolved target's cached [`fsref.FileRef`](internal/fsref/fsref.go:1) type character is checked *before* any open. Only regular files (`f`) are opened for reading. Character/block devices (`HISTFILE=/dev/null`, `/dev/urandom`), FIFOs, sockets, and directories are rejected outright and recorded as a non-fatal anomaly (`target_type_rejected`) — this closes the evasion techniques of pointing `HISTFILE` at `/dev/null` to erase history or at `/dev/urandom`/a named pipe to hang or exhaust the collector.
  3. **Space Guard & Size Cap Gating**: Regular files are checked against both the destination Space Guard quota and the `--max-artefact-bytes` limit before opening, preventing malicious or oversized history targets from filling output disk space.
  4. **No Secondary Walk**: The fetch is a single targeted open by resolved path — Stage 3 never re-invokes the directory walker, preserving the single-pass traversal guarantee.

---

## Standalone CLI & Configuration Architecture

### Modern Go CLI Design (`cmd/forensic-scan/main.go`)

```
Usage: forensic-scan [OPTIONS] --dest <DIR>

Options:
  -m, --mount <PATH>             Mount point of image to collect from (default: "/")
  -o, --dest <DIR>               Output destination directory (required)
  -p, --profile <NAME>           Collection profile (e.g., "triage", "offline-fast", "full")
  -c, --config <PATH>            Path to configuration file
  -a, --artifacts <DIR>          Custom artifact rules directory
  -s, --target-os <OS>           Target OS (mandatory when --mount is not "/": linux, darwin, freebsd)
      --metadata-only            Zero-copy mode: collect timeline, paths, and hashes only (no file content)
      --max-collection-bytes <N> Total extracted content ceiling across run (default: 1GB; 0 = unlimited)
      --min-free-space <N>       Safety buffer for destination disk free space (default: 500MB)
      --max-artefact-bytes <N>   Max bytes extracted per individual file (default: 5MB)
      --start-days <N>           Only collect files modified within N days
      --end-days <N>             Only collect files older than N days
      --workers <N>              Parallel workers for hashing/extraction (default: NumCPU)
      --buffer-limit <BYTES>     Max in-memory buffer size per file (default: 1MB)
      --cross-device             Allow traversal across filesystem boundaries
      --format <FMT>             Output format: "jsonl" (default), "bodyfile", "legacy-text"
  -v, --verbose                  Enable detailed logging
      --version                  Display engine version and build info
```

### Modern YAML Configuration (`config.yaml`)

```yaml
version: "1.0"

collection:
  default_profile: "offline-fast"
  workers: 8
  buffer_limit_bytes: 1048576 # 1 MB
  cross_device: false
  output_format: "jsonl" # jsonl, bodyfile, legacy-text

storage_governance:
  metadata_only: false
  max_collection_bytes: 1073741824 # 1 GB total content quota
  min_free_space_bytes: 524288000  # 500 MB minimum destination free space
  circuit_breaker_action: "pause_content_and_warn" # graceful degradation to metadata-only

artefact_extraction:
  max_bytes_per_file: 5242880 # 5 MB per individual file
  log_window_lines: 5000       # Slices last 5000 lines of active logs
  inline_threshold_bytes: 65536 # <64KB stored inline in JSONL stream

hashing:
  algorithms:
    - sha256
    - md5

filtering:
  global_exclude_paths:
    - "/proc"
    - "/sys"
    - "/dev"
    - "/run"
    - "/tmp"
  exclude_filesystem_types:
    - "proc"
    - "sysfs"
    - "devtmpfs"
    - "devpts"
```

---

## Phase 1 Implementation & Migration Roadmap

The migration replaces legacy UAC components in discrete, verified stages:

```
┌────────────────────────────────────────────────────────────────────────┐
│ Milestone 1: Pure Go Model & Engine Core Extraction                    │
│ - Implement pkg/artifact (Definition, Profile, Schema)                 │
│ - Decouple pkg/engine from internal/uacdata and internal/uacpath       │
│ - Integrate standard YAML parser (yaml.v3)                             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Milestone 2: Clean Offline Collectors & Pipeline                       │
│ - Refactor collector/ to use native artifact definitions               │
│ - Standardize stat, find, hash, and targeted artefact collectors       │
│ - Implement Space Guard & Circuit Breaker (statvfs quota enforcement)  │
│ - Implement Stage-2 Dynamic Expansion for shell history                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Milestone 3: Embedded Pure-Go Artifact Catalog + Migration Gate        │
│ - Build automated UAC-YAML → native-YAML converter tool                │
│ - Convert all 490+ offline artifacts; hand-review flagged edge cases   │
│ - Embed catalog using Go 1.16+ //go:embed                              │
│ - GATE: differential harness must show 100% parity before Milestone 5  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Milestone 4: Modern CLI & Config Overhaul                              │
│ - Create cmd/forensic-scan (modern flags, JSON manifest output)        │
│ - Replace uac.conf parser with clean YAML configuration                │
│ - Deprecate legacy UAC CLI flags                                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Milestone 5: Standalone Verification & Cleanup                         │
│ - Implement native Go filesystem fixture test suite                    │
│ - Add golden-file regression tests for all collectors                  │
│ - Add ENOSPC circuit-breaker and storage quota simulation tests        │
│ - Confirm Milestone 3 parity gate passed on real-world trees           │
│ - Retire test/harness UAC shell runners and test/uacfull archives      │
│ - Delete internal/artifact/parse.go quirks and bodyfilelists hacks     │
│ - Remove internal/uacdata/uac.tar.gz and generation scripts            │
└────────────────────────────────────────────────────────────────────────┘
```

### Detailed Milestone Tasks

#### Milestone 1: Pure Go Model & Engine Core Extraction
- Define [`pkg/artifact/definition.go`](pkg/artifact/definition.go:1) with type-safe `Definition`, `FilterCriteria`, and `ScopeCriteria`.
- Implement JSON Schema validation to verify artifact rules at load time.
- Decouple [`run.go`](run.go:1) into [`pkg/engine/engine.go`](pkg/engine/engine.go:1) with clear `Options` and `Context` structures.

#### Milestone 2: Clean Offline Collectors & Pipeline
- Refactor [`collector/collector.go:31`](collector/collector.go:31) to consume compiled native rules.
- Replace legacy raw `fileCollector` with `artefactCollector` supporting bounded surgical extraction, log windowing, and space-guard integration.
- Implement destination storage governance in [`internal/spool/spool.go:1`](internal/spool/spool.go:1) with continuous `statvfs` probing and automatic circuit breaking.
- Simplify [`collector/collectors.go:36`](collector/collectors.go:36) (`statCollector`, `findCollector`, `hashCollector`, `artefactCollector`), eliminating raw filesystem tree mirroring.
- Replace [`internal/rules/histfile.go:44`](internal/rules/histfile.go:44) and [`internal/rules/bodyfilelists.go:108`](internal/rules/bodyfilelists.go:108) with a generic multi-stage pipeline.

#### Milestone 3: Embedded Pure-Go Artifact Catalog + Migration Verification Gate

Converting the 490+ artifact catalog by hand risks silently dropping forensic coverage, and the UAC differential harness ([`test/harness/main.go:1`](test/harness/main.go:1)) is currently the only ground-truth oracle proving collection fidelity against real filesystem trees. This milestone therefore treats catalog migration as a **verified conversion**, not a rewrite from scratch, and explicitly forbids retiring the harness until parity is proven:

- **Build an automated converter** (`tools/uacyaml2native`) that ingests the existing UAC corpus ([`internal/uacdata/uac.tar.gz`](internal/uacdata/uac.tar.gz)) via the current parser ([`internal/artifact/parse.go:1`](internal/artifact/parse.go:1)) and mechanically emits native `Definition` YAML records, preserving `id`, `paths`, `permissions`, `size`/`mtime`/`ctime`/`atime` ranges, and `supported_os` fields 1:1.
- **Flag, don't guess, on ambiguity**: constructs the hand-rolled parser resolves via quirky heuristics (bash-eval comments, unquoted `%user_home%` tokens, shell-style size suffixes) are emitted with a `# MIGRATION-REVIEW:` comment rather than silently translated, forcing a human decision on each edge case instead of a best-effort guess.
- **Author native definitions only for genuinely new targets** not present in the UAC corpus (if any); everything else is machine-converted and human-reviewed, not hand-authored from scratch.
- Embed the resulting catalog directly via `//go:embed rules/*.yaml`.
- **Migration Gate (blocks Milestone 5)**: Run the existing differential harness ([`test/harness/main.go:1`](test/harness/main.go:1)) with the pure Go engine and converted catalog against the same fixtures used to validate the original 14.9× speedup (synthetic fixture, `/usr/share/doc`, `/usr/lib/python3`). The gate evaluates 100% parity across `stat` (bodyfile), `find` (path listings), and `hash` collectors, proving that rule matching, scope resolution, and traversal logic are completely faithful to UAC. File extraction is deliberately decoupled from legacy UAC raw directory mirroring, validating that the new zero-copy / targeted artefact model captures identical target paths without failing on legacy uncompressed directory comparisons. Only after this gate is green does Milestone 5 proceed to remove [`internal/uacdata/uac.tar.gz`](internal/uacdata/uac.tar.gz) and [`internal/uacdata/gen/main.go`](internal/uacdata/gen/main.go:1).

#### Milestone 4: Modern CLI & Config Overhaul
- Implement [`cmd/forensic-scan/main.go`](cmd/forensic-scan/main.go:1) using standard flags or `spf13/pflag` with mandatory `--target-os` on external mount points, `--metadata-only` zero-copy flag, and storage quota options (`--max-collection-bytes`, `--min-free-space`, `--max-artefact-bytes`).
- Replace [`internal/config/config.go`](internal/config/config.go:1) with structured YAML loader supporting `storage_governance` and `artefact_extraction` sections.
- Standardize output directory layout:
  ```
  output/
  ├── manifest.json
  ├── summary.txt
  ├── stream/
  │   └── records.jsonl
  ├── bodyfile/
  │   └── bodyfile.txt
  ├── lists/
  │   └── ...
  ├── hashes/
  │   └── ...
  └── artefacts/
      ├── artefacts.tar.zst (single compressed spool for non-inline artefacts)
      └── ...
  ```

#### Milestone 5: Standalone Verification & Cleanup
- **Prerequisite**: Milestone 3's differential migration gate must be green — do not proceed with harness removal until parity is confirmed.
- Build automated test suite using `test/fixture` ([`test/fixture/fixture.go:1`](test/fixture/fixture.go:1)) without external shell dependencies.
- Implement golden-file tests validating bit-exact bodyfiles, streaming `.jsonl` records, path lists, and cryptographic hashes, generated from the final differential harness run so the golden files carry forward the same ground truth rather than re-deriving new baselines from an unverified engine.
- Validate special node safety (ensuring FIFOs and devices are never opened) and subvolume boundary traversal (btrfs/ZFS/APFS/LVM).
- Validate anchor-based user-home rule binding on a large synthetic `/home` fixture (10,000+ directories) to confirm bounded memory/startup cost.
- Validate Stage 3 targeted fetch rejects `/dev/null`, FIFO, and symlink-escape `HISTFILE` values without hanging or escaping containment.
- Validate Storage Circuit Breaker: simulate an `ENOSPC` / low-space condition on a synthetic small volume; verify that the engine gracefully halts content extraction, logs a degraded warning in the manifest, and successfully runs metadata and timeline generation to 100% completion without crashing.
- Delete [`test/harness/main.go`](test/harness/main.go:1), [`test/uacfull/`](test/uacfull/), and [`internal/artifact/parse.go`](internal/artifact/parse.go:1) only after the above are green.

---

## Architectural Comparison & Invariants

To maintain forensic integrity throughout the transition, the following invariants are strictly preserved:

1. **Deterministic Output**: For identical input filesystem states and configurations, collection output remains bit-for-bit identical across runs.
2. **Minimal Inode Overhead**: Exactly one stat operation per traversed node; zero speculative file opens for metadata filtering.
3. **Strict Special Node Safety**: Block and character devices, FIFOs, and sockets are metadata-inspected via `statx`/`lstat` only; they are strictly never opened for content reading — including secondary targets discovered dynamically (e.g. `HISTFILE` values) in the multi-stage pipeline.
4. **Hostile Image & User Root Containment**: Mount paths, user/service-account home directory anchors, and dynamically discovered secondary targets are all validated via [`fsref.ResolveBeneath()`](internal/fsref/beneath.go:1) to prevent symlink traversal escapes; violations are logged, not silently dropped.
5. **Smart Subvolume Traversal**: Auto-prunes pseudo/virtual filesystems while seamlessly crossing same-disk subvolumes (btrfs, ZFS, APFS, LVM thin pools) without naive device-boundary truncation.
6. **Enterprise Scope Coverage**: Dual user resolution (`/etc/passwd` + disk enumeration across `/home`, `/root`, `/Users`, `/var/home`, and service-account homes under `/opt`, `/var/lib`, `/srv`) guarantees coverage of enterprise / domain-joined VM snapshot profiles even when identity servers are unreachable; orphaned homes are never silently omitted, only annotated (`account_source: "unindexed_directory"`).
7. **Bounded Rule Growth**: User- and service-account-scoped artifacts are bound to anchors at traversal time, not expanded into the compiled rule set at startup — live rule count stays proportional to catalog size and traversal depth, not to the number of discovered home directories.
8. **Evidence Immutability**: All source operations are strictly read-only (`O_RDONLY`).
9. **Error Resiliency**: Individual bad sectors, permission denials, broken symlinks, or rejected dynamic targets are recorded in the manifest as evidence anomalies and do not abort the collection run.
10. **Storage Confinement & Bounded Extraction**: Output is spooled directly to disk; memory is bounded by buffer limits regardless of filesystem inode count. Content extraction is bounded by `--max-artefact-bytes` per file, and global extracted content is capped by `--max-collection-bytes`.
11. **Verified Migration Parity**: The native artifact catalog is not considered authoritative until the automated converter's output passes the differential harness against UAC on the same fixtures used to validate the original 14.9× speedup; the harness is retained until this gate is green.
12. **Zero-Fatal-ENOSPC Guarantee**: The engine never crashes or aborts prematurely due to destination volume space exhaustion. When destination free disk space falls below `--min-free-space`, the storage circuit breaker trips, gracefully pausing content extraction while allowing zero-byte-cost metadata, bodyfiles, and cryptographic hashes to complete cleanly.

---

## Conclusion & Recommendations

Rewriting the forensic collection engine in pure Go—eliminating the embedded UAC tarball, legacy shell parsers, and compatibility shims—significantly elevates the project's maintainability, security, and operational reliability.

Crucially, addressing the real-world operational hazard of `no space left on device` (`ENOSPC`) errors shifts the architectural paradigm: **the engine eliminates unconstrained bulk file copying in favor of Zero-Copy Metadata Triage and Targeted Artefact Extraction**. By combining continuous `statvfs` space probing, global collection quotas, surgical log windowing, and non-fatal circuit breakers with its proven high-performance core (single-pass walk, stat caching, parallel content broker), the pure Go engine delivers bulletproof forensic collections that complete reliably even under tight disk constraints.

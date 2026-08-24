// Package uacscan runs a full offline collection against a mounted image:
// given a set of options it resolves the target operating system, compiles
// the applicable rules from UAC's artifact definitions, walks the filesystem
// once, and spools the results beneath a freshly created run directory.
//
// cmd/uacscan is a thin CLI wrapper around Run; other Go programs can import
// this package and call Run directly to embed a collection without shelling
// out to the built binary.
package uacscan

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/biolog71/uacscan/collector"
	"github.com/biolog71/uacscan/internal/artifact"
	"github.com/biolog71/uacscan/internal/config"
	"github.com/biolog71/uacscan/internal/content"
	"github.com/biolog71/uacscan/internal/fsref"
	"github.com/biolog71/uacscan/internal/mounts"
	"github.com/biolog71/uacscan/internal/outdir"
	"github.com/biolog71/uacscan/internal/passwd"
	"github.com/biolog71/uacscan/internal/rules"
	"github.com/biolog71/uacscan/internal/spool"
	"github.com/biolog71/uacscan/internal/targetos"
	"github.com/biolog71/uacscan/internal/uacdata"
	"github.com/biolog71/uacscan/internal/walk"
)

// Options is everything one collection run needs, as uacscan's command line
// describes it.
type Options struct {
	Mount        string
	Dest         string
	BaseName     string
	ArtifactDir  string
	ConfPath     string
	TargetOS     string
	Include      string
	Exclude      string
	ExcludePaths string
	StartDays    int
	EndDays      int
	BufferLimit  int64
	Workers      int
	CrossDevice  bool
	Verbose      bool

	// Warnf, if set, receives non-fatal warnings as they occur: artifact
	// definitions that failed to parse, rules that failed to compile, and,
	// when Verbose is set, per-file read errors and walk errors. Warnings
	// are dropped silently if Warnf is nil.
	Warnf func(msg string)
}

func (o Options) warn(msg string) {
	if o.Warnf != nil {
		o.Warnf(msg)
	}
}

// ManifestEntry describes one spool file a run produced.
type ManifestEntry struct {
	Collector string // rule id that produced it
	Kind      string // bodyfile | hashes | paths | copies | errors
	Path      string // absolute path of the spool file
	Rel       string // path relative to the output root
	Lines     int64
	Bytes     int64
}

// Summary reports what a completed run did.
type Summary struct {
	OutputDir      string
	Hostname       string
	DefinitionsSrc string
	TargetOS       string
	TargetOSReason string
	MountPoint     string
	Mounts         int
	Rules          int
	Files          int64
	Dirs           int64
	SkippedDirs    int64
	WalkErrors     int64
	FileErrors     int64
	Elapsed        time.Duration
	Manifest       []ManifestEntry
}

// Run performs one collection according to o, writing spooled output beneath
// a freshly created run directory under o.Dest.
func Run(o Options) (Summary, error) {
	mount := strings.TrimSuffix(o.Mount, "/")
	if mount == "" {
		mount = "/"
	}
	if fi, err := os.Stat(mount); err != nil || !fi.IsDir() {
		return Summary{}, fmt.Errorf("mount point %s is not a directory", mount)
	}

	// Definitions come from the copy baked into the binary unless the operator
	// points at a checkout, so a collection needs nothing but the executable.
	artFS, conf, source, err := loadDefinitions(o.ArtifactDir, o.ConfPath)
	if err != nil {
		return Summary{}, err
	}

	docs, parseErrs := artifact.LoadFS(artFS)
	for f, err := range parseErrs {
		o.warn(fmt.Sprintf("warning: %s: %v", f, err))
	}
	if len(docs) == 0 {
		return Summary{}, fmt.Errorf("no artifact definitions found in %s", source)
	}

	osTarget, osReason, err := targetos.Resolve(o.TargetOS, mount)
	if err != nil {
		return Summary{}, err
	}

	// Every run writes into its own freshly created directory. Two collections
	// sharing one would interleave their spool writes mid-line and produce a
	// bodyfile with records from both images spliced together -- the right
	// number of lines, no error, and wrong evidence.
	hostname := outdir.Hostname(mount)
	baseName := o.BaseName
	if baseName == "" {
		baseName = outdir.Name(hostname, string(osTarget), time.Now())
	}
	outDir, err := outdir.Create(o.Dest, baseName)
	if err != nil {
		return Summary{}, fmt.Errorf("creating the output directory: %w", err)
	}

	// The mount table lets exclude_file_system be honoured. Only mounts at or
	// beneath the collection root matter, and their paths are recorded
	// image-relative like everything else.
	mountTable := mounts.Load().Under(mount)

	accounts := passwd.Load(mount)
	if osTarget == targetos.Unknown && o.Verbose {
		o.warn("warning: the image could not be identified; no artifacts will be filtered by operating system")
	}
	if !accounts.Known() && o.Verbose {
		o.warn(fmt.Sprintf("warning: no passwd file under %s; no_user/no_group rules will be skipped", mount))
	}

	env := &rules.Env{
		MountPoint:         mount,
		Now:                time.Now(),
		OS:                 osTarget,
		StartDateDays:      o.StartDays,
		EndDateDays:        o.EndDays,
		EnableMtime:        conf.EnableFindMtime,
		EnableAtime:        conf.EnableFindAtime,
		EnableCtime:        conf.EnableFindCtime,
		HashAlgorithm:      conf.HashAlgorithm,
		Mounts:             mountTable,
		UserHomes:          accounts.Homes,
		ShellUserHomes:     accounts.ShellHomes,
		ExcludeNamePattern: conf.ExcludeNamePattern,
		MaxDepth:           conf.MaxDepth,
		OutputDir:          outDir,
	}
	// Set independently: an image may have a passwd file and no group file, or
	// the reverse, and conflating them produces opposite errors.
	if accounts.KnownUsers() {
		env.UIDs = accounts.UIDs
	}
	if accounts.KnownGroups() {
		env.GIDs = accounts.GIDs
	}

	inc := splitGlobs(o.Include)
	exc := splitGlobs(o.Exclude)

	var compiled []*rules.Rule
	for _, d := range docs {
		if !selected(d.Source, inc, exc) {
			continue
		}
		for _, e := range d.Artifacts {
			r, err := rules.Compile(e, d, env)
			if err != nil {
				o.warn(fmt.Sprintf("warning: %s: %v", e.ID(), err))
				continue
			}
			if r != nil {
				compiled = append(compiled, r)
			}
		}
	}
	// When both bodyfile2filelists.yaml and bodyfile/bodyfile.yaml were
	// selected, drop the standalone artifacts it shadows in a real UAC run --
	// see rules.ApplyBodyfileListsShadowing for exactly which ones and why.
	compiled = rules.ApplyBodyfileListsShadowing(compiled)
	if len(compiled) == 0 {
		return Summary{}, fmt.Errorf("no offline rules apply to %s selected by %q", osTarget, o.Include)
	}

	store, err := spool.NewStore(outDir)
	if err != nil {
		return Summary{}, err
	}
	defer store.Close()

	cache := fsref.NewCache(mount)
	broker := content.NewBroker()
	broker.BufferLimit = o.BufferLimit
	broker.Workers = o.Workers

	ctx := &collector.Context{
		Cache:      cache,
		Broker:     broker,
		Store:      store,
		Env:        env,
		OutputRoot: outDir,
	}
	broker.OnError = func(path, consumer string, err error) {
		ctx.RecordError(path, consumer, err)
		if o.Verbose {
			o.warn(fmt.Sprintf("read error: %s (%s): %v", path, consumer, err))
		}
	}

	cs := make([]collector.Collector, 0, len(compiled))
	for _, r := range compiled {
		c, err := collector.New(r, ctx)
		if err != nil {
			return Summary{}, err
		}
		cs = append(cs, c)
	}

	// Everything pruned for every rule: what the operator asked to skip, what
	// uac.conf excludes, and the mount points of the excluded filesystem types.
	pruned := splitList(o.ExcludePaths)
	pruned = append(pruned, conf.ExcludePathPattern...)
	pruned = append(pruned, mountTable.PointsForTypes(conf.ExcludeFileSystem)...)
	excludeGlobs := compileExcludes(pruned)

	// The run's own output must never be collected, and a glob cannot express
	// that reliably: the operator chooses the path, so it may contain glob
	// metacharacters or be given relative to the working directory. Both the
	// run directory and the destination are pruned by resolved absolute path.
	skipReal := map[string]bool{}
	for _, p := range []string{outDir, o.Dest} {
		if c := fsref.Canonical(p); c != "" {
			skipReal[c] = true
		}
	}

	w := &walk.Walker{
		Root:         mount,
		Cache:        cache,
		Broker:       broker,
		Set:          rules.NewSet(compiled),
		Collectors:   cs,
		ExcludePaths: excludeGlobs,
		SkipReal:     skipReal,
		CrossDevice:  o.CrossDevice,
		Recorded:     ctx.RecordedErrors,
		OnError: func(path string, err error) {
			ctx.RecordError(path, "walk", err)
			if o.Verbose {
				o.warn(fmt.Sprintf("walk error: %s: %v", path, err))
			}
		},
	}

	start := time.Now()
	if err := w.Walk(); err != nil {
		return Summary{}, err
	}
	elapsed := time.Since(start)

	if err := store.Close(); err != nil {
		return Summary{}, err
	}

	st := w.Stats()
	man := store.Manifest()
	entries := make([]ManifestEntry, len(man))
	for i, e := range man {
		entries[i] = ManifestEntry{
			Collector: e.Collector,
			Kind:      e.Kind,
			Path:      e.Path,
			Rel:       e.Rel,
			Lines:     e.Lines,
			Bytes:     e.Bytes,
		}
	}

	return Summary{
		OutputDir:      outDir,
		Hostname:       hostname,
		DefinitionsSrc: source,
		TargetOS:       string(osTarget),
		TargetOSReason: osReason,
		MountPoint:     mount,
		Mounts:         len(mountTable),
		Rules:          len(compiled),
		Files:          st.Files,
		Dirs:           st.Dirs,
		SkippedDirs:    st.SkippedDirs,
		WalkErrors:     st.Errors,
		FileErrors:     st.Recorded,
		Elapsed:        elapsed,
		Manifest:       entries,
	}, nil
}

// loadDefinitions resolves where the artifact definitions and uac.conf come
// from. Embedded by default; a directory override switches both, so the
// definitions and the configuration always come from the same place rather
// than being silently mixed.
func loadDefinitions(artDir, confPath string) (fs.FS, *config.Config, string, error) {
	if artDir == "" {
		artFS, err := uacdata.Artifacts()
		if err != nil {
			return nil, nil, "", err
		}
		full, err := uacdata.FS()
		if err != nil {
			return nil, nil, "", err
		}
		conf, err := config.LoadFS(full, "config/uac.conf")
		if err != nil {
			return nil, nil, "", fmt.Errorf("reading the embedded uac.conf: %w", err)
		}
		if confPath != "" {
			if conf, err = config.Load(confPath); err != nil {
				return nil, nil, "", fmt.Errorf("loading %s: %w", confPath, err)
			}
		}
		release, commit := uacdata.Version()
		return artFS, conf, fmt.Sprintf("embedded (UAC %s, commit %s)", release, commit), nil
	}

	if confPath == "" {
		confPath = filepath.Join(filepath.Dir(strings.TrimSuffix(artDir, "/")), "config", "uac.conf")
	}
	conf, err := config.Load(confPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("loading %s: %w", confPath, err)
	}
	return os.DirFS(artDir), conf, artDir, nil
}

// splitList splits a comma-separated flag value, dropping blanks.
func splitList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitGlobs(s string) []rules.Glob {
	var out []rules.Glob
	for _, p := range splitList(s) {
		out = append(out, rules.CompileGlob(p))
	}
	return out
}

func selected(source string, inc, exc []rules.Glob) bool {
	for _, g := range exc {
		if g.Match(source) {
			return false
		}
	}
	if len(inc) == 0 {
		return true
	}
	for _, g := range inc {
		if g.Match(source) {
			return true
		}
	}
	return false
}

// compileExcludes turns prune paths into globs, one for the path itself and
// one for everything under it. Duplicates are dropped and the result sorted, so
// the compiled set does not depend on the order the sources were appended in.
//
// The output directory is deliberately not here. It used to be, expressed as a
// glob against the mount-relative path of the destination's *parent*, which
// failed three ways: the actual run directory was never named, a destination
// containing glob metacharacters was read as a pattern, and a relative
// destination never matched the absolute paths the walk produces. It is pruned
// by resolved path instead; see Walker.SkipReal.
func compileExcludes(paths []string) []rules.Glob {
	set := map[string]bool{}
	for _, p := range paths {
		if p = strings.TrimSpace(p); p != "" {
			set[p] = true
		}
	}
	out := make([]rules.Glob, 0, len(set)*2)
	for _, p := range slices.Sorted(maps.Keys(set)) {
		out = append(out, rules.CompileGlob(p), rules.CompileGlob(p+"/*"))
	}
	return out
}

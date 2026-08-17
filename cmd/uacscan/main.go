// Command uacscan collects UAC's offline artifacts from a mounted image in a
// single filesystem pass.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"uacscan/collector"
	"uacscan/internal/artifact"
	"uacscan/internal/config"
	"uacscan/internal/content"
	"uacscan/internal/fsref"
	"uacscan/internal/mounts"
	"uacscan/internal/outdir"
	"uacscan/internal/passwd"
	"uacscan/internal/rules"
	"uacscan/internal/spool"
	"uacscan/internal/targetos"
	"uacscan/internal/uacdata"
	"uacscan/internal/walk"
)

// options is everything one collection run needs, as the command line
// describes it.
//
// A struct rather than a positional parameter list: there were fourteen, nine
// of them strings, and at that width a call site says nothing about which
// argument is which while any two neighbours can be transposed without the
// compiler noticing.
type options struct {
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
	CrossDevice  bool
	Verbose      bool
}

func main() {
	var o options
	flag.StringVar(&o.Mount, "m", "/", "mount point of the image to collect from")
	flag.StringVar(&o.Dest, "o", "", "destination directory; a uniquely named run directory is created inside it (required)")
	flag.StringVar(&o.BaseName, "output-base-name", "", "name for the run directory (default: uacscan-<hostname>-<os>-<timestamp>)")
	flag.StringVar(&o.ArtifactDir, "a", "", "override the embedded artifact definitions with a UAC artifacts directory")
	flag.StringVar(&o.ConfPath, "c", "", "uac.conf to load (default: <artifacts>/../config/uac.conf)")
	flag.StringVar(&o.TargetOS, "s", "", "operating system of the image ("+targetos.Names()+"); detected from the image if omitted")
	flag.StringVar(&o.Include, "include", "*", "comma-separated globs selecting artifacts, e.g. 'bodyfile/*,system/*'")
	flag.StringVar(&o.Exclude, "exclude", "", "comma-separated globs of artifacts to skip")
	flag.StringVar(&o.ExcludePaths, "exclude-path", "/proc,/sys,/dev,/run", "comma-separated paths pruned from the walk")
	flag.IntVar(&o.StartDays, "start-date-days", 0, "only files changed within this many days (0 disables)")
	flag.IntVar(&o.EndDays, "end-date-days", 0, "only files older than this many days (0 disables)")
	flag.Int64Var(&o.BufferLimit, "buffer-limit", content.DefaultBufferLimit, "files at or below this size are buffered whole")
	flag.BoolVar(&o.CrossDevice, "cross-device", false, "allow the walk to leave the root filesystem")
	flag.BoolVar(&o.Verbose, "v", false, "report progress and per-file errors")

	extract := flag.String("extract", "", "write the embedded UAC definitions to this directory and exit")
	showVer := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *showVer {
		release, commit := uacdata.Version()
		fmt.Printf("uacscan (embedded UAC artifacts %s, commit %s)\n", release, commit)
		return
	}
	if *extract != "" {
		if err := extractTo(*extract); err != nil {
			fmt.Fprintf(os.Stderr, "uacscan: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if o.Dest == "" {
		fmt.Fprintln(os.Stderr, "uacscan: -o is required")
		flag.Usage()
		os.Exit(2)
	}
	if err := run(o); err != nil {
		fmt.Fprintf(os.Stderr, "uacscan: %v\n", err)
		os.Exit(1)
	}
}

func run(o options) error {
	mount := strings.TrimSuffix(o.Mount, "/")
	if mount == "" {
		mount = "/"
	}
	if fi, err := os.Stat(mount); err != nil || !fi.IsDir() {
		return fmt.Errorf("mount point %s is not a directory", mount)
	}

	// Definitions come from the copy baked into the binary unless the operator
	// points at a checkout, so a collection needs nothing but the executable.
	artFS, conf, source, err := loadDefinitions(o.ArtifactDir, o.ConfPath)
	if err != nil {
		return err
	}

	docs, parseErrs := artifact.LoadFS(artFS)
	for f, err := range parseErrs {
		fmt.Fprintf(os.Stderr, "warning: %s: %v\n", f, err)
	}
	if len(docs) == 0 {
		return fmt.Errorf("no artifact definitions found in %s", source)
	}

	osTarget, osReason, err := targetos.Resolve(o.TargetOS, mount)
	if err != nil {
		return err
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
		return fmt.Errorf("creating the output directory: %w", err)
	}

	// The mount table lets exclude_file_system be honoured. Only mounts at or
	// beneath the collection root matter, and their paths are recorded
	// image-relative like everything else.
	mountTable := mounts.Load().Under(mount)

	accounts := passwd.Load(mount)
	if osTarget == targetos.Unknown && o.Verbose {
		fmt.Fprintln(os.Stderr, "warning: the image could not be identified; no artifacts will be filtered by operating system")
	}
	if !accounts.Known() && o.Verbose {
		fmt.Fprintf(os.Stderr, "warning: no passwd file under %s; no_user/no_group rules will be skipped\n", mount)
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
				fmt.Fprintf(os.Stderr, "warning: %s: %v\n", e.ID(), err)
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
		return fmt.Errorf("no offline rules apply to %s selected by %q", osTarget, o.Include)
	}

	store, err := spool.NewStore(outDir)
	if err != nil {
		return err
	}
	defer store.Close()

	cache := fsref.NewCache(mount)
	broker := content.NewBroker()
	broker.BufferLimit = o.BufferLimit

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
			fmt.Fprintf(os.Stderr, "read error: %s (%s): %v\n", path, consumer, err)
		}
	}

	cs := make([]collector.Collector, 0, len(compiled))
	for _, r := range compiled {
		c, err := collector.New(r, ctx)
		if err != nil {
			return err
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
				fmt.Fprintf(os.Stderr, "walk error: %s: %v\n", path, err)
			}
		},
	}

	start := time.Now()
	if err := w.Walk(); err != nil {
		return err
	}
	elapsed := time.Since(start)

	if err := store.Close(); err != nil {
		return err
	}

	st := w.Stats()
	fmt.Printf("output        : %s\n", outDir)
	fmt.Printf("host          : %s\n", hostname)
	fmt.Printf("definitions   : %s\n", source)
	fmt.Printf("target os     : %s (%s)\n", osTarget, osReason)
	if n := len(mountTable); n > 0 {
		fmt.Printf("mounts        : %d under the collection root\n", n)
	}
	fmt.Printf("mount point   : %s\n", mount)
	fmt.Printf("rules         : %d\n", len(compiled))
	fmt.Printf("files visited : %d\n", st.Files)
	fmt.Printf("directories   : %d (%d skipped)\n", st.Dirs, st.SkippedDirs)
	fmt.Printf("walk errors   : %d\n", st.Errors)
	fmt.Printf("file errors   : %d (see uacscan/errors.txt)\n", st.Recorded)
	fmt.Printf("elapsed       : %s", elapsed.Round(time.Millisecond))
	if st.Files > 0 {
		fmt.Printf("  (%.1f us/file)", float64(elapsed.Microseconds())/float64(st.Files))
	}
	fmt.Println()

	man := store.Manifest()
	fmt.Printf("\noutputs (%d):\n", len(man))
	for _, e := range man {
		fmt.Printf("  %-50s %8d lines  %9d bytes\n", e.Rel, e.Lines, e.Bytes)
	}
	return nil
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

// extractTo writes the embedded definitions out, for operators who want to
// read or edit them.
func extractTo(dir string) error {
	n := 0
	err := uacdata.Extract(dir, func(name string, data []byte) error {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return err
		}
		// These are UAC's own definitions, not evidence: they are meant to be
		// read and edited, so they keep ordinary permissions.
		if err := os.WriteFile(full, data, 0644); err != nil { //nolint:gosec // definitions are public, not collected data
			return err
		}
		n++
		return nil
	})
	if err != nil {
		return err
	}
	release, commit := uacdata.Version()
	fmt.Printf("extracted %d files (UAC %s, commit %s) to %s\n", n, release, commit, dir)
	return nil
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

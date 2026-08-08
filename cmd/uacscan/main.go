// Command uacscan collects UAC's offline artifacts from a mounted image in a
// single filesystem pass.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
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

func main() {
	var (
		mount     = flag.String("m", "/", "mount point of the image to collect from")
		outDir    = flag.String("o", "", "destination directory; a uniquely named run directory is created inside it (required)")
		baseName  = flag.String("output-base-name", "", "name for the run directory (default: uacscan-<hostname>-<os>-<timestamp>)")
		artDir    = flag.String("a", "", "override the embedded artifact definitions with a UAC artifacts directory")
		extract   = flag.String("extract", "", "write the embedded UAC definitions to this directory and exit")
		showVer   = flag.Bool("version", false, "print version information and exit")
		include   = flag.String("include", "*", "comma-separated globs selecting artifacts, e.g. 'bodyfile/*,system/*'")
		exclude   = flag.String("exclude", "", "comma-separated globs of artifacts to skip")
		startDays = flag.Int("start-date-days", 0, "only files changed within this many days (0 disables)")
		endDays   = flag.Int("end-date-days", 0, "only files older than this many days (0 disables)")
		excl      = flag.String("exclude-path", "/proc,/sys,/dev,/run", "comma-separated paths pruned from the walk")
		crossDev  = flag.Bool("cross-device", false, "allow the walk to leave the root filesystem")
		bufLimit  = flag.Int64("buffer-limit", content.DefaultBufferLimit, "files at or below this size are buffered whole")
		confPath  = flag.String("c", "", "uac.conf to load (default: <artifacts>/../config/uac.conf)")
		targetOS  = flag.String("s", "", "operating system of the image ("+targetos.Names()+"); detected from the image if omitted")
		verbose   = flag.Bool("v", false, "report progress and per-file errors")
	)
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
	if *outDir == "" {
		fmt.Fprintln(os.Stderr, "uacscan: -o is required")
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*mount, *outDir, *baseName, *artDir, *include, *exclude, *excl, *confPath, *targetOS,
		*startDays, *endDays, *bufLimit, *crossDev, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "uacscan: %v\n", err)
		os.Exit(1)
	}
}

func run(mount, dest, baseName, artDir, include, exclude, excludePaths, confPath, targetOS string,
	startDays, endDays int, bufLimit int64, crossDev, verbose bool) error {

	mount = strings.TrimSuffix(mount, "/")
	if mount == "" {
		mount = "/"
	}
	if fi, err := os.Stat(mount); err != nil || !fi.IsDir() {
		return fmt.Errorf("mount point %s is not a directory", mount)
	}

	// Definitions come from the copy baked into the binary unless the operator
	// points at a checkout, so a collection needs nothing but the executable.
	artFS, conf, source, err := loadDefinitions(artDir, confPath)
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

	osTarget, osReason, err := targetos.Resolve(targetOS, mount)
	if err != nil {
		return err
	}

	// Every run writes into its own freshly created directory. Two collections
	// sharing one would interleave their spool writes mid-line and produce a
	// bodyfile with records from both images spliced together -- the right
	// number of lines, no error, and wrong evidence.
	hostname := outdir.Hostname(mount)
	if baseName == "" {
		baseName = outdir.Name(hostname, string(osTarget), time.Now())
	}
	outDir, err := outdir.Create(dest, baseName)
	if err != nil {
		return fmt.Errorf("creating the output directory: %w", err)
	}

	// The mount table lets exclude_file_system be honoured. Only mounts at or
	// beneath the collection root matter, and their paths are recorded
	// image-relative like everything else.
	mountTable := mounts.Load().Under(mount)

	accounts := passwd.Load(mount)
	if osTarget == targetos.Unknown && verbose {
		fmt.Fprintln(os.Stderr, "warning: the image could not be identified; no artifacts will be filtered by operating system")
	}
	if !accounts.Known() && verbose {
		fmt.Fprintf(os.Stderr, "warning: no passwd file under %s; no_user/no_group rules will be skipped\n", mount)
	}

	env := &rules.Env{
		MountPoint:         mount,
		Now:                time.Now(),
		OS:                 osTarget,
		StartDateDays:      startDays,
		EndDateDays:        endDays,
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
	if accounts.Known() {
		env.UIDs, env.GIDs = accounts.UIDs, accounts.GIDs
	}

	inc := splitGlobs(include)
	exc := splitGlobs(exclude)

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
	if len(compiled) == 0 {
		return fmt.Errorf("no offline rules apply to %s selected by %q", osTarget, include)
	}

	store, err := spool.NewStore(outDir)
	if err != nil {
		return err
	}
	defer store.Close()

	cache := fsref.NewCache(mount)
	broker := content.NewBroker()
	broker.BufferLimit = bufLimit

	ctx := &collector.Context{
		Cache:      cache,
		Broker:     broker,
		Store:      store,
		Env:        env,
		OutputRoot: outDir,
	}
	broker.OnError = func(path, consumer string, err error) {
		ctx.RecordError(path, consumer, err)
		if verbose {
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

	// The tool's own output must never be collected as evidence.
	for _, p := range conf.ExcludePathPattern {
		excludePaths += "," + p
	}
	// The globally excluded filesystem types prune for every rule.
	for _, p := range mountTable.PointsForTypes(conf.ExcludeFileSystem) {
		excludePaths += "," + p
	}
	excludeGlobs := compileExcludes(excludePaths, dest, mount)

	w := &walk.Walker{
		Root:         mount,
		Cache:        cache,
		Broker:       broker,
		Set:          rules.NewSet(compiled),
		Collectors:   cs,
		ExcludePaths: excludeGlobs,
		CrossDevice:  crossDev,
		Recorded:     ctx.RecordedErrors,
		OnError: func(path string, err error) {
			ctx.RecordError(path, "walk", err)
			if verbose {
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
		if err := os.WriteFile(full, data, 0644); err != nil {
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

func splitGlobs(s string) []rules.Glob {
	var out []rules.Glob
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, rules.CompileGlob(p))
		}
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

// compileExcludes builds the global prune set. The output directory is always
// included: collecting our own output would be both wrong and unbounded.
func compileExcludes(list, outDir, mount string) []rules.Glob {
	set := map[string]bool{}
	for _, p := range strings.Split(list, ",") {
		if p = strings.TrimSpace(p); p != "" {
			set[p] = true
		}
	}
	if abs, err := filepath.Abs(outDir); err == nil {
		if rel := fsref.Rel(abs, mount); strings.HasPrefix(rel, "/") && rel != "/" {
			set[rel] = true
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]rules.Glob, 0, len(keys)*2)
	for _, k := range keys {
		out = append(out, rules.CompileGlob(k), rules.CompileGlob(k+"/*"))
	}
	return out
}

// Command uacscan collects UAC's offline artifacts from a mounted image in a
// single filesystem pass.
package main

import (
	"flag"
	"fmt"
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
	"uacscan/internal/passwd"
	"uacscan/internal/rules"
	"uacscan/internal/spool"
	"uacscan/internal/walk"
)

func main() {
	var (
		mount     = flag.String("m", "/", "mount point of the image to collect from")
		outDir    = flag.String("o", "", "output directory (required)")
		artDir    = flag.String("a", "", "UAC artifacts directory (required)")
		include   = flag.String("include", "*", "comma-separated globs selecting artifacts, e.g. 'bodyfile/*,system/*'")
		exclude   = flag.String("exclude", "", "comma-separated globs of artifacts to skip")
		startDays = flag.Int("start-date-days", 0, "only files changed within this many days (0 disables)")
		endDays   = flag.Int("end-date-days", 0, "only files older than this many days (0 disables)")
		excl      = flag.String("exclude-path", "/proc,/sys,/dev,/run", "comma-separated paths pruned from the walk")
		crossDev  = flag.Bool("cross-device", false, "allow the walk to leave the root filesystem")
		bufLimit  = flag.Int64("buffer-limit", content.DefaultBufferLimit, "files at or below this size are buffered whole")
		confPath  = flag.String("c", "", "uac.conf to load (default: <artifacts>/../config/uac.conf)")
		verbose   = flag.Bool("v", false, "report progress and per-file errors")
	)
	flag.Parse()

	if *outDir == "" || *artDir == "" {
		fmt.Fprintln(os.Stderr, "uacscan: -o and -a are required")
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*mount, *outDir, *artDir, *include, *exclude, *excl, *confPath,
		*startDays, *endDays, *bufLimit, *crossDev, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "uacscan: %v\n", err)
		os.Exit(1)
	}
}

func run(mount, outDir, artDir, include, exclude, excludePaths, confPath string,
	startDays, endDays int, bufLimit int64, crossDev, verbose bool) error {

	mount = strings.TrimSuffix(mount, "/")
	if mount == "" {
		mount = "/"
	}
	if fi, err := os.Stat(mount); err != nil || !fi.IsDir() {
		return fmt.Errorf("mount point %s is not a directory", mount)
	}

	docs, parseErrs := artifact.LoadDir(artDir)
	for f, err := range parseErrs {
		fmt.Fprintf(os.Stderr, "warning: %s: %v\n", f, err)
	}
	if len(docs) == 0 {
		return fmt.Errorf("no artifacts found under %s", artDir)
	}

	if confPath == "" {
		confPath = filepath.Join(filepath.Dir(strings.TrimSuffix(artDir, "/")), "config", "uac.conf")
	}
	conf, err := config.Load(confPath)
	if err != nil {
		return fmt.Errorf("loading %s: %w", confPath, err)
	}

	accounts := passwd.Load(mount)
	if !accounts.Known() && verbose {
		fmt.Fprintf(os.Stderr, "warning: no passwd file under %s; no_user/no_group rules will be skipped\n", mount)
	}

	env := &rules.Env{
		MountPoint:    mount,
		Now:           time.Now(),
		StartDateDays: startDays,
		EndDateDays:   endDays,
		EnableMtime:   conf.EnableFindMtime,
		EnableAtime:   conf.EnableFindAtime,
		EnableCtime:   conf.EnableFindCtime,
		HashAlgorithm: conf.HashAlgorithm,
		UserHomes:     accounts.Homes,
		OutputDir:     outDir,
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
		return fmt.Errorf("no offline rules selected by %q", include)
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
	excludeGlobs := compileExcludes(excludePaths, outDir, mount)

	w := &walk.Walker{
		Root:         mount,
		Cache:        cache,
		Broker:       broker,
		Set:          rules.NewSet(compiled),
		Collectors:   cs,
		ExcludePaths: excludeGlobs,
		CrossDevice:  crossDev,
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
	fmt.Printf("mount point   : %s\n", mount)
	fmt.Printf("rules         : %d\n", len(compiled))
	fmt.Printf("files visited : %d\n", st.Files)
	fmt.Printf("directories   : %d (%d skipped)\n", st.Dirs, st.SkippedDirs)
	fmt.Printf("walk errors   : %d\n", st.Errors)
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

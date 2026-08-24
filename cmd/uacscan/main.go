// Command uacscan collects UAC's offline artifacts from a mounted image in a
// single filesystem pass.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/biolog71/uacscan"
	"github.com/biolog71/uacscan/internal/content"
	"github.com/biolog71/uacscan/internal/targetos"
	"github.com/biolog71/uacscan/internal/uacdata"
)

func main() {
	var o uacscan.Options
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
	flag.IntVar(&o.Workers, "workers", runtime.NumCPU(),
		"files whose content is read, hashed and copied concurrently (1 = fully serial)")
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

	o.Warnf = func(msg string) { fmt.Fprintln(os.Stderr, msg) }

	summary, err := uacscan.Run(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, "uacscan: %v\n", err)
		os.Exit(1)
	}
	report(summary)
}

// report prints a completed run's summary the way operators expect to see it
// on the terminal.
func report(s uacscan.Summary) {
	fmt.Printf("output        : %s\n", s.OutputDir)
	fmt.Printf("host          : %s\n", s.Hostname)
	fmt.Printf("definitions   : %s\n", s.DefinitionsSrc)
	fmt.Printf("target os     : %s (%s)\n", s.TargetOS, s.TargetOSReason)
	if s.Mounts > 0 {
		fmt.Printf("mounts        : %d under the collection root\n", s.Mounts)
	}
	fmt.Printf("mount point   : %s\n", s.MountPoint)
	fmt.Printf("rules         : %d\n", s.Rules)
	fmt.Printf("files visited : %d\n", s.Files)
	fmt.Printf("directories   : %d (%d skipped)\n", s.Dirs, s.SkippedDirs)
	fmt.Printf("walk errors   : %d\n", s.WalkErrors)
	fmt.Printf("file errors   : %d (see uacscan/errors.txt)\n", s.FileErrors)
	fmt.Printf("elapsed       : %s", s.Elapsed.Round(time.Millisecond))
	if s.Files > 0 {
		fmt.Printf("  (%.1f us/file)", float64(s.Elapsed.Microseconds())/float64(s.Files))
	}
	fmt.Println()

	fmt.Printf("\noutputs (%d):\n", len(s.Manifest))
	for _, e := range s.Manifest {
		fmt.Printf("  %-50s %8d lines  %9d bytes\n", e.Rel, e.Lines, e.Bytes)
	}
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

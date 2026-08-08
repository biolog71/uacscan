// Package walk traverses the image once and dispatches every path to every
// collector.
//
// UAC runs one find(1) per artifact entry -- around 490 of them, twenty of
// which start at / and traverse the whole tree. This walker visits each inode
// once, resolves it once, and lets all the rules look at the same record.
package walk

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"uacscan/collector"
	"uacscan/internal/content"
	"uacscan/internal/fsref"
	"uacscan/internal/rules"
)

// Walker performs the single pass.
type Walker struct {
	// Root is the mount point. Recorded paths are relative to it, so results
	// read /etc/passwd no matter where the image happened to be mounted.
	Root string

	Cache  *fsref.Cache
	Broker *content.Broker
	Set    *rules.Set

	Collectors []collector.Collector

	// ExcludePaths prunes globally: excluded filesystems, the tool's own output
	// directory, anything the operator asked to skip. Unlike a rule's own
	// exclusions these really do stop the descent, because no rule can want
	// what is behind them.
	ExcludePaths []rules.Glob

	// CrossDevice allows the walk to leave the root filesystem. Off by default:
	// on a mounted image, crossing a device boundary means leaving the evidence.
	CrossDevice bool

	// OnError receives traversal problems. They are reported, never fatal.
	OnError func(path string, err error)

	// Progress, if set, is called once per directory entered.
	Progress func(path string, files int64)

	rootDev  uint64
	files    int64
	dirs     int64
	skipped  int64
	errCount int64
}

// Stats summarises a completed walk.
type Stats struct {
	Files       int64
	Dirs        int64
	SkippedDirs int64
	Errors      int64
}

func (w *Walker) Stats() Stats {
	return Stats{Files: w.files, Dirs: w.dirs, SkippedDirs: w.skipped, Errors: w.errCount}
}

type frame struct {
	real  string
	rel   string
	depth int
}

// Walk traverses the tree. It returns an error only when a collector reports
// that it is broken; per-file problems are routed to OnError and the walk
// continues, because unreadable files are normal on real images.
func (w *Walker) Walk() error {
	root := strings.TrimSuffix(w.Root, "/")
	if root == "" {
		root = "/"
	}

	rootRef, err := fsref.Resolve(root, "/", 0)
	if err != nil {
		return fmt.Errorf("cannot stat the walk root %s: %w", root, err)
	}
	w.rootDev = rootRef.Dev

	if err := w.visit(rootRef); err != nil {
		return err
	}

	stack := []frame{{real: root, rel: "/", depth: 0}}
	for len(stack) > 0 {
		fr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(fr.real)
		if err != nil {
			w.reportErr(fr.rel, err)
			continue
		}
		w.dirs++
		if w.Progress != nil {
			w.Progress(fr.rel, w.files)
		}

		// os.ReadDir sorts by name, which keeps output reproducible across
		// runs. Push in reverse so the stack pops in sorted order.
		var dirs []frame
		for _, de := range entries {
			realPath := join(fr.real, de.Name())
			relPath := join(fr.rel, de.Name())

			if w.globallyExcluded(relPath) {
				continue
			}

			ref, err := fsref.Resolve(realPath, relPath, fr.depth+1)
			if err != nil {
				w.reportErr(relPath, err)
				continue
			}
			if !w.CrossDevice && ref.Dev != w.rootDev {
				continue
			}

			if err := w.visit(ref); err != nil {
				return err
			}

			// Never descend through a symlink: that is how a walk ends up in a
			// loop, or outside the image entirely.
			if ref.IsDir() {
				if w.shouldDescend(relPath) {
					dirs = append(dirs, frame{real: realPath, rel: relPath, depth: fr.depth + 1})
				} else {
					w.skipped++
				}
			}
		}
		sort.Slice(dirs, func(i, j int) bool { return dirs[i].rel > dirs[j].rel })
		stack = append(stack, dirs...)
	}

	// Second phase, for artifacts whose paths only became known during the
	// walk -- a shell history file named inside an rc file, say.
	for _, c := range w.Collectors {
		if f, ok := c.(collector.Finisher); ok {
			if err := f.Finish(); err != nil {
				return fmt.Errorf("finishing collector: %w", err)
			}
		}
	}
	return w.flush()
}

// visit primes the cache, dispatches to every collector, then lets the broker
// serve whoever asked for the file's bytes.
func (w *Walker) visit(ref *fsref.FileRef) error {
	w.files++
	w.Cache.Set(ref)
	w.Broker.Reset()

	for _, c := range w.Collectors {
		if err := c.InspectFile(ref.Path); err != nil {
			// A collector reporting itself broken stops the scan; a bad *file*
			// never reaches here, it is recorded inside the collector.
			return fmt.Errorf("collector failed on %s: %w", ref.Path, err)
		}
	}
	// The open happens last, only if a rule matched. Nothing speculative is
	// ever opened, which is what keeps device nodes in the image's /dev from
	// resolving to the examiner's own hardware.
	return w.Broker.Run(ref)
}

// shouldDescend asks whether anything could match inside this directory. A
// directory is skipped only when the rule set cannot reach it and every
// collector agrees it is prunable.
func (w *Walker) shouldDescend(rel string) bool {
	if w.Set != nil && !w.Set.MayContainMatches(rel) {
		return false
	}
	for _, c := range w.Collectors {
		p, ok := c.(collector.Pruner)
		if !ok || !p.ShouldSkipDir(rel) {
			return true
		}
	}
	return len(w.Collectors) == 0
}

func (w *Walker) globallyExcluded(rel string) bool {
	for _, g := range w.ExcludePaths {
		if g.Match(rel) {
			return true
		}
	}
	return false
}

func (w *Walker) flush() error {
	for _, c := range w.Collectors {
		if f, ok := c.(collector.Flusher); ok {
			if err := f.Flush(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *Walker) reportErr(path string, err error) {
	w.errCount++
	if w.OnError != nil {
		w.OnError(path, err)
	}
}

func join(dir, name string) string {
	if strings.HasSuffix(dir, "/") {
		return dir + name
	}
	return dir + "/" + name
}

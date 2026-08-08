// Package collector defines the collector contract and the four offline
// collectors UAC supports: file, find, stat and hash.
//
// The exported interface is deliberately narrow, because collectors are meant
// to be pluggable and some will come from outside this repository:
//
//	InspectFile(path string) error
//	ScanResults() (any, error)
//
// InspectFile takes a path, not a stat buffer, but no collector ever calls
// stat itself. The walker resolves each path exactly once and primes a
// single-entry cache before dispatching; because every collector is called for
// the same path consecutively, that cache has a perfect hit rate. Without it,
// 479 compiled rules would mean 479 stat calls per file.
package collector

import (
	"fmt"
	"sort"
	"sync"

	"uacscan/internal/content"
	"uacscan/internal/fsref"
	"uacscan/internal/rules"
	"uacscan/internal/spool"
)

// Collector is the contract every collector satisfies.
type Collector interface {
	// InspectFile examines one path and records whatever it finds. A returned
	// error means the collector itself is broken -- its spool file cannot be
	// written, the output disk is full -- and the scan should stop. Problems
	// with the *file* (unreadable, vanished, bad sector) are recorded as
	// results and must not be returned: unreadable files are routine on real
	// images, and one of them must never abort a multi-hour acquisition.
	InspectFile(path string) error

	// ScanResults returns this collector's results. Implementations return a
	// stream that reads from disk, never a materialised slice.
	ScanResults() (any, error)
}

// Pruner is an optional interface. A push-only collector cannot tell the walker
// to skip a subtree, and pruning is what keeps exclusions cheap, so collectors
// that know a directory is irrelevant may say so. The walker skips a directory
// only when every collector agrees.
type Pruner interface {
	ShouldSkipDir(path string) bool
}

// Flusher is an optional interface for collectors with buffered or deferred
// work. The walker calls it before ScanResults is valid.
type Flusher interface {
	Flush() error
}

// Finisher is an optional interface for collectors whose work cannot happen
// during the walk. The walker calls Finish once, after the traversal, which is
// what makes the two-phase artifacts possible: a shell history file named
// inside an rc file is not knowable until that rc file has been read.
type Finisher interface {
	Finish() error
}

// Context is the machinery shared by every collector in one scan.
type Context struct {
	// Cache is the single-entry stat memo the walker primes.
	Cache *fsref.Cache
	// Broker opens a matched file once and shares it with all consumers.
	Broker *content.Broker
	// Store owns the output tree.
	Store *spool.Store
	// Env carries the date range and the image's account database.
	Env *rules.Env
	// OutputRoot is where collected file bytes are written.
	OutputRoot string

	// Lists holds paths discovered during the walk by list-producing rules,
	// keyed the way rules.normalizeListKey names them. The is_file_list
	// collectors read from here once the walk is over.
	listMu sync.Mutex
	lists  map[string][]string

	errOnce sync.Once
	errW    *spool.Writer
	errErr  error
}

// AddToList records a path discovered by a list-producing rule.
func (c *Context) AddToList(key, path string) {
	c.listMu.Lock()
	defer c.listMu.Unlock()
	if c.lists == nil {
		c.lists = map[string][]string{}
	}
	for _, existing := range c.lists[key] {
		if existing == path {
			return
		}
	}
	c.lists[key] = append(c.lists[key], path)
}

// List returns the paths recorded under a key, sorted so the output does not
// depend on the order files happened to be visited in.
func (c *Context) List(key string) []string {
	c.listMu.Lock()
	defer c.listMu.Unlock()
	out := append([]string(nil), c.lists[key]...)
	sort.Strings(out)
	return out
}

// RecordError writes a per-file problem to the errors spool. It deliberately
// returns nothing: callers must not treat a bad file as a reason to stop.
func (c *Context) RecordError(path, stage string, err error) {
	c.errOnce.Do(func() {
		c.errW, c.errErr = c.Store.Open("uacscan", "errors", "/uacscan", "errors.txt")
	})
	if c.errW == nil {
		return
	}
	_ = c.errW.Writef("%s|%s|%s", path, stage, err)
}

// ref returns the already-resolved record for path. A cache miss is not an
// error; it just means somebody called the collector outside a walk.
func (c *Context) ref(path string) (*fsref.FileRef, error) {
	return c.Cache.Get(path)
}

// New builds the collector for one compiled rule.
func New(r *rules.Rule, ctx *Context) (Collector, error) {
	base := base{rule: r, ctx: ctx}
	switch r.Kind {
	case rules.KindStat:
		return &statCollector{base: base}, nil
	case rules.KindFind:
		return &findCollector{base: base}, nil
	case rules.KindHash:
		return &hashCollector{base: base}, nil
	case rules.KindFile:
		return &fileCollector{base: base}, nil
	case rules.KindList:
		return &listCollector{base: base}, nil
	}
	return nil, fmt.Errorf("unknown collector kind %q", r.Kind)
}

type base struct {
	rule *rules.Rule
	ctx  *Context
	w    *spool.Writer
}

// ShouldSkipDir lets a rule's own exclusions prune the walk.
//
// Note the semantic shift from UAC: there, each artifact's exclude_path_pattern
// prunes its own find. Here the walk is shared, so a directory is only really
// skipped when no rule wants it -- the walker asks every collector. The results
// are identical either way; only the cost differs.
func (b *base) ShouldSkipDir(path string) bool {
	return b.rule.Excluded(path, baseName(path))
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func (b *base) writer(kind, defaultName string) (*spool.Writer, error) {
	if b.w != nil {
		return b.w, nil
	}
	name := b.rule.OutputFile
	if name == "" {
		name = defaultName
	}
	w, err := b.ctx.Store.Open(b.rule.ID, kind, b.rule.OutputDir, name)
	if err != nil {
		return nil, err
	}
	b.w = w
	return w, nil
}

func (b *base) Flush() error {
	if b.w == nil {
		return nil
	}
	return b.w.Flush()
}

// Result is the streamed record type shared by the line-oriented collectors.
type Result struct {
	Collector string
	Line      string
}

// Package spool persists scan results to disk as they are produced.
//
// Results never accumulate in memory: a bodyfile for a million-inode image is
// well over a hundred megabytes on its own, and it is one of hundreds of
// outputs. Each output target gets an append-only file with a buffered writer,
// which is crash-tolerant by construction (a torn final line is the only
// failure mode), greppable while a long acquisition is still running, and
// streams back with no seeking.
//
// The line format is UAC's own, not JSON, so the output tree is byte-comparable
// against the shell implementation and readable by the same downstream tools.
package spool

import (
	"bufio"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Entry describes one spool file in the manifest.
type Entry struct {
	Collector string // rule id that produced it
	Kind      string // bodyfile | hashes | paths | copies | errors
	Path      string // absolute path of the spool file
	Rel       string // path relative to the output root
	Lines     int64
	Bytes     int64
}

// Writer is an append-only line sink.
type Writer struct {
	mu    sync.Mutex
	f     *os.File
	w     *bufio.Writer
	lines int64
	bytes int64
	rel   string
}

func (w *Writer) WriteLine(s string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.w.WriteString(s)
	if err != nil {
		return err
	}
	if err := w.w.WriteByte('\n'); err != nil {
		return err
	}
	w.lines++
	w.bytes += int64(n) + 1
	return nil
}

func (w *Writer) Writef(format string, args ...any) error {
	return w.WriteLine(fmt.Sprintf(format, args...))
}

func (w *Writer) Lines() int64 { return w.lines }

func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Flush()
}

func (w *Writer) Close() error {
	if err := w.Flush(); err != nil {
		w.f.Close()
		return err
	}
	return w.f.Close()
}

// Store owns the output tree and hands out writers. Writers are memoised per
// relative path, so several rules sharing an output_file append to one file
// exactly as they do under UAC.
type Store struct {
	Root string

	mu      sync.Mutex
	writers map[string]*Writer
	kinds   map[string]string
	owners  map[string]string
}

func NewStore(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, err
	}
	return &Store{
		Root:    root,
		writers: map[string]*Writer{},
		kinds:   map[string]string{},
		owners:  map[string]string{},
	}, nil
}

// Open returns the writer for an output file, creating it on first use. dir is
// the artifact's output_directory, relative to the output root.
func (s *Store) Open(collector, kind, dir, name string) (*Writer, error) {
	rel := filepath.Join(sanitizeDir(dir), SanitizeName(name))
	s.mu.Lock()
	defer s.mu.Unlock()
	if w, ok := s.writers[rel]; ok {
		return w, nil
	}
	full := filepath.Join(s.Root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	w := &Writer{f: f, w: bufio.NewWriterSize(f, 64*1024), rel: rel}
	s.writers[rel] = w
	s.kinds[rel] = kind
	s.owners[rel] = collector
	return w, nil
}

// Manifest lists every spool file written, newest counts included. It is what
// a composite collector's ScanResults returns: opening hundreds of streams
// eagerly would defeat the point of spooling in the first place.
func (s *Store) Manifest() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, 0, len(s.writers))
	for rel, w := range s.writers {
		if w.lines == 0 {
			continue // UAC removes empty outputs; so do we
		}
		out = append(out, Entry{
			Collector: s.owners[rel],
			Kind:      s.kinds[rel],
			Path:      filepath.Join(s.Root, rel),
			Rel:       rel,
			Lines:     w.lines,
			Bytes:     w.bytes,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out
}

// Close flushes every writer and removes the ones that stayed empty.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	for rel, w := range s.writers {
		empty := w.lines == 0
		if err := w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		if empty {
			os.Remove(filepath.Join(s.Root, rel))
		}
	}
	return firstErr
}

// Lines streams a spool file back without loading it. This is what a leaf
// collector's ScanResults hands the caller.
func Lines(path string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		f, err := os.Open(path)
		if err != nil {
			yield("", err)
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for sc.Scan() {
			if !yield(sc.Text(), nil) {
				return
			}
		}
		if err := sc.Err(); err != nil {
			yield("", err)
		}
	}
}

// SanitizeName mirrors UAC's output filename sanitiser: characters that cannot
// appear in a filename on every supported platform become underscores.
func SanitizeName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.Trim(name, "/")
	repl := strings.NewReplacer(
		"/", "_", `\`, "_", "*", "_", "?", "_",
		":", "_", `"`, "_", "<", "_", ">", "_",
	)
	name = repl.Replace(name)
	for strings.Contains(name, "__") {
		name = strings.ReplaceAll(name, "__", "_")
	}
	if name == "" {
		return "_"
	}
	return name
}

func sanitizeDir(dir string) string {
	return strings.TrimPrefix(filepath.Clean("/"+dir), "/")
}

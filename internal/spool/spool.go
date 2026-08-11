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
//
// # Divergence from UAC
//
// One difference is deliberate: control bytes in a path are escaped before a
// record is written. UAC passes filenames through find(1) and stat(1) verbatim,
// so a file whose name contains a newline splits its record in two and lets a
// suspect fabricate evidence by naming a file. See escapeControl.
//
// The output is also written 0600 under 0700 directories rather than
// world-readable, because a collection contains whatever the image did --
// /etc/shadow, private keys, credential stores.
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
	"syscall"
	"time"
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

// WriteLine appends one record.
//
// Control bytes are escaped first, so that one call always produces exactly one
// line. This is a deliberate divergence from UAC: see escapeControl.
func (w *Writer) WriteLine(s string) error {
	s = escapeControl(s)
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
		_ = w.f.Close() // the flush error is the one worth reporting
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

// NewStore prepares an output tree.
//
// The directory must be absent or empty. Appending a second acquisition to an
// existing one produces line-oriented outputs containing both while copied
// files are selectively overwritten, and the manifest counts only what this run
// wrote -- a mixture that looks like a single coherent collection and is not.
func NewStore(root string) (*Store, error) {
	if err := reserve(root); err != nil {
		return nil, err
	}
	return &Store{
		Root:    root,
		writers: map[string]*Writer{},
		kinds:   map[string]string{},
		owners:  map[string]string{},
	}, nil
}

// reserveMarker is created exclusively to claim an output directory.
const reserveMarker = ".uacscan-collection"

// OutputFilePerm and OutputDirPerm keep a collection readable only by the
// examiner who made it.
//
// The output is not ordinary program output: a collection contains /etc/shadow,
// SSH private keys, browser credential stores and anything else the artifacts
// asked for. Written 0644 under a 0755 directory, as it was, every local user
// on a shared analysis workstation could read the contents of the image --
// material the tool went to some length to read safely in the first place.
const (
	OutputFilePerm = 0600
	OutputDirPerm  = 0700
)

// reserve claims root for this collection.
//
// Checking that a directory is empty and then creating it is two steps: two
// stores opened before either writes would both see an empty directory, both
// succeed, and later append into the same files. Creating a marker with O_EXCL
// is one step, so exactly one caller can win.
func reserve(root string) error {
	if err := os.MkdirAll(root, OutputDirPerm); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == reserveMarker {
			return fmt.Errorf("output directory %s is already claimed by another collection", root)
		}
		return fmt.Errorf("output directory %s is not empty; "+
			"a collection must not be mixed with an earlier one", root)
	}

	f, err := os.OpenFile(filepath.Join(root, reserveMarker),
		os.O_CREATE|os.O_EXCL|os.O_WRONLY, OutputFilePerm)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("output directory %s is already claimed by another collection", root)
		}
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "claimed %s\n", time.Now().UTC().Format(time.RFC3339))
	return err
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
	if err := os.MkdirAll(filepath.Dir(full), OutputDirPerm); err != nil {
		return nil, err
	}
	// O_NOFOLLOW so that a symlink sitting where an output file should go
	// cannot redirect results out of the collection directory. O_APPEND
	// because several rules legitimately share one output_file within a run;
	// across runs the caller is expected to supply a fresh directory, which is
	// what NewStore enforces.
	fd, err := syscall.Open(full,
		syscall.O_CREAT|syscall.O_WRONLY|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		OutputFilePerm)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: full, Err: err}
	}
	f := os.NewFile(uintptr(fd), full)
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
			// UAC removes empty outputs. A failure to remove one leaves a
			// harmless zero-length file and must not mask a real write error.
			_ = os.Remove(filepath.Join(s.Root, rel))
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

// escapeControl renders control bytes printably, so that data taken from the
// image cannot end a record early.
//
// A filename is attacker-controlled: Linux permits every byte in one except '/'
// and NUL. Written raw into a line-oriented output, a name containing a newline
// closes its record and opens another, so naming a file
//
//	evil\n0|/etc/cron.d/backdoor|99|-rwxrwxrwx|0|0|0|0|0|0|0
//
// puts a complete, valid mactime record for a file that never existed into the
// bodyfile. It parses in Autopsy or log2timeline as genuine evidence, and
// nothing downstream can tell it from a real one. The same trick reaches the
// hash manifests, where a forged line can assert a known-good digest for a
// system binary.
//
// This is a deliberate divergence from UAC, which inherits the raw behaviour
// from find(1) and stat(1). The output is byte-compared against UAC's, so the
// escaping is confined to bytes that cannot legitimately appear in a record:
// anything below 0x20, plus DEL. Ordinary paths -- including spaces, brackets,
// backslashes and UTF-8 -- pass through untouched, so the comparison is
// unaffected in every case that is not already an attack.
//
// The name is escaped rather than dropped: a file named this way is itself
// evidence, and the examiner should see it.
func escapeControl(s string) string {
	if !hasControl(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20 || c == 0x7f:
			// Anything else unprintable, including NUL and the ESC that would
			// otherwise let a filename write escape sequences to the
			// examiner's terminal when they cat the output.
			fmt.Fprintf(&b, `\x%02x`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
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

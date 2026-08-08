// Package uacdata carries UAC's artifact definitions inside the binary.
//
// The corpus is 1.8 MB of small YAML files that compresses to about 50 KiB, so
// it rides along as a single tar.gz rather than as an embedded directory tree.
// It is unpacked into memory at first use -- never onto disk. An acquisition
// tool should not scatter temporary files across the examiner's machine, and
// there is no reason to: the whole corpus is smaller than a single collected
// log file.
//
// This archive is carved out of the full one the harness uses, not packed from
// the checkout a second time, so the two cannot disagree about what UAC 3.3.0
// contains. Regenerate in this order:
//
//	go generate ./test/uacfull ./internal/uacdata
package uacdata

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:generate go run ./gen -mode data -from ../../test/uacfull/uac-full.tar.gz -out uac.tar.gz

//go:embed uac.tar.gz
var archive []byte

var (
	once     sync.Once
	unpacked *memFS
	unpackNo error
)

// FS returns the embedded UAC tree: artifacts/, config/ and profiles/, plus a
// VERSION file recording which UAC checkout it was built from.
func FS() (fs.FS, error) {
	once.Do(func() { unpacked, unpackNo = unpack(archive) })
	if unpackNo != nil {
		return nil, unpackNo
	}
	return unpacked, nil
}

// Artifacts returns just the artifact definitions, rooted so that paths read
// "files/system/etc.yaml" exactly as they do with a real checkout.
func Artifacts() (fs.FS, error) {
	f, err := FS()
	if err != nil {
		return nil, err
	}
	return fs.Sub(f, "artifacts")
}

// Version reports the UAC release and commit the embedded corpus was built
// from. A collection must be traceable to the definitions that produced it.
func Version() (release, commit string) {
	release, commit = "unknown", "unknown"
	f, err := FS()
	if err != nil {
		return release, commit
	}
	b, err := fs.ReadFile(f, "VERSION")
	if err != nil {
		return release, commit
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "uac_version":
			release = v
		case "uac_commit":
			commit = v
		}
	}
	return release, commit
}

// Extract writes the embedded tree to dir, for operators who want the
// definitions on disk to read or modify.
func Extract(dir string, write func(name string, data []byte) error) error {
	f, err := FS()
	if err != nil {
		return err
	}
	return fs.WalkDir(f, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(f, p)
		if err != nil {
			return err
		}
		return write(p, data)
	})
}

// ---------------------------------------------------------------------------
// in-memory read-only filesystem
// ---------------------------------------------------------------------------

func unpack(gz []byte) (*memFS, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("uacdata: %w", err)
	}
	defer zr.Close()

	m := &memFS{files: map[string][]byte{}, dirs: map[string]map[string]bool{".": {}}}
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("uacdata: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(hdr.Name)
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("uacdata: %s: %w", name, err)
		}
		m.files[name] = data
		m.addParents(name)
	}
	if len(m.files) == 0 {
		return nil, errors.New("uacdata: embedded archive is empty")
	}
	return m, nil
}

type memFS struct {
	files map[string][]byte
	// dirs maps a directory to the set of names directly inside it.
	dirs map[string]map[string]bool
}

func (m *memFS) addParents(name string) {
	for {
		parent := path.Dir(name)
		if m.dirs[parent] == nil {
			m.dirs[parent] = map[string]bool{}
		}
		m.dirs[parent][path.Base(name)] = true
		if parent == "." {
			return
		}
		name = parent
	}
}

func (m *memFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if data, ok := m.files[name]; ok {
		return &memFile{info: memInfo{name: path.Base(name), size: int64(len(data))},
			r: bytes.NewReader(data)}, nil
	}
	if _, ok := m.dirs[name]; ok {
		entries, err := m.ReadDir(name)
		if err != nil {
			return nil, err
		}
		return &memFile{info: memInfo{name: path.Base(name), dir: true}, entries: entries}, nil
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (m *memFS) ReadFile(name string) ([]byte, error) {
	data, ok := m.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: fs.ErrNotExist}
	}
	// Callers must not be able to corrupt the embedded corpus.
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

func (m *memFS) ReadDir(name string) ([]fs.DirEntry, error) {
	children, ok := m.dirs[name]
	if !ok {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	out := make([]fs.DirEntry, 0, len(children))
	for child := range children {
		full := child
		if name != "." {
			full = name + "/" + child
		}
		info := memInfo{name: child}
		if data, isFile := m.files[full]; isFile {
			info.size = int64(len(data))
		} else {
			info.dir = true
		}
		out = append(out, memDirEntry{info})
	}
	// Sorted, so a walk over the embedded corpus is as reproducible as one
	// over a real directory.
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

type memFile struct {
	info    memInfo
	r       *bytes.Reader
	entries []fs.DirEntry
	offset  int
}

func (f *memFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *memFile) Close() error               { return nil }

func (f *memFile) Read(p []byte) (int, error) {
	if f.r == nil {
		return 0, &fs.PathError{Op: "read", Path: f.info.name, Err: fs.ErrInvalid}
	}
	return f.r.Read(p)
}

func (f *memFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if f.entries == nil {
		return nil, &fs.PathError{Op: "readdir", Path: f.info.name, Err: fs.ErrInvalid}
	}
	if n <= 0 {
		rest := f.entries[f.offset:]
		f.offset = len(f.entries)
		return rest, nil
	}
	if f.offset >= len(f.entries) {
		return nil, io.EOF
	}
	end := min(f.offset+n, len(f.entries))
	out := f.entries[f.offset:end]
	f.offset = end
	return out, nil
}

type memInfo struct {
	name string
	size int64
	dir  bool
}

func (i memInfo) Name() string       { return i.name }
func (i memInfo) Size() int64        { return i.size }
func (i memInfo) IsDir() bool        { return i.dir }
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) Sys() any           { return nil }

func (i memInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0555
	}
	return 0444
}

type memDirEntry struct{ info memInfo }

func (e memDirEntry) Name() string               { return e.info.name }
func (e memDirEntry) IsDir() bool                { return e.info.dir }
func (e memDirEntry) Type() fs.FileMode          { return e.info.Mode().Type() }
func (e memDirEntry) Info() (fs.FileInfo, error) { return e.info, nil }

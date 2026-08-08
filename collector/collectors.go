package collector

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"iter"
	"os"
	"path/filepath"
	"strings"

	"uacscan/internal/content"
	"uacscan/internal/fsref"
	"uacscan/internal/spool"
)

// ---------------------------------------------------------------------------
// stat: mactime bodyfile
// ---------------------------------------------------------------------------

type statCollector struct{ base }

// InspectFile emits one mactime bodyfile line.
//
// The field layout matches what UAC produces with
// stat -c "0|%N|%i|%A|%u|%g|%s|%X|%Y|%Z|%W", including the leading MD5 column
// left as a literal 0 and the quote-stripping UAC applies afterwards with sed.
func (c *statCollector) InspectFile(path string) error {
	f, err := c.ctx.ref(path)
	if err != nil {
		c.ctx.RecordError(path, "stat", err)
		return nil
	}
	if !c.rule.Match(f, c.ctx.Env) {
		return nil
	}
	w, err := c.writer("bodyfile", "bodyfile.txt")
	if err != nil {
		return err // the collector is broken, not the file
	}

	name := f.Path
	if f.IsSymlink() {
		if target, lerr := f.Link(); lerr == nil && target != "" {
			name = f.Path + " -> " + target
		}
	}
	var btime int64
	if f.HasBtime {
		btime = f.Btime.Unix()
	}
	return w.Writef("0|%s|%d|%s|%d|%d|%d|%d|%d|%d|%d",
		name, f.Ino, f.ModeString(), f.UID, f.GID, f.Size,
		f.Atime.Unix(), f.Mtime.Unix(), f.Ctime.Unix(), btime)
}

func (c *statCollector) ScanResults() (any, error) { return c.stream(), nil }

func (b *base) stream() iter.Seq2[Result, error] {
	return func(yield func(Result, error) bool) {
		if b.w == nil {
			return
		}
		if err := b.w.Flush(); err != nil {
			yield(Result{}, err)
			return
		}
		for _, e := range b.ctx.Store.Manifest() {
			if e.Collector != b.rule.ID {
				continue
			}
			for line, err := range spool.Lines(e.Path) {
				if !yield(Result{Collector: b.rule.ID, Line: line}, err) {
					return
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// find: record matching paths
// ---------------------------------------------------------------------------

type findCollector struct{ base }

func (c *findCollector) InspectFile(path string) error {
	f, err := c.ctx.ref(path)
	if err != nil {
		c.ctx.RecordError(path, "find", err)
		return nil
	}
	if !c.rule.Match(f, c.ctx.Env) {
		return nil
	}
	// The two find artifacts that pipe results through a command (getcap,
	// lsattr) become native per-file checks: a capability is an xattr, and the
	// immutable flag arrives in the statx we already did.
	switch {
	case strings.HasPrefix(c.rule.Command, "getcap"):
		caps, err := getxattr(f.Real, "security.capability")
		if err != nil || len(caps) == 0 {
			return nil
		}
	case strings.Contains(c.rule.Command, "lsattr"):
		set, known := f.Immutable()
		if !known {
			c.ctx.RecordError(path, "immutable", fmt.Errorf("filesystem does not report the immutable attribute"))
			return nil
		}
		if !set {
			return nil
		}
	}
	w, err := c.writer("paths", "find.txt")
	if err != nil {
		return err
	}
	return w.WriteLine(f.Path)
}

func (c *findCollector) ScanResults() (any, error) { return c.stream(), nil }

// ---------------------------------------------------------------------------
// hash
// ---------------------------------------------------------------------------

type hashCollector struct {
	base
	algorithms []string
	writers    map[string]*spool.Writer
}

func (c *hashCollector) InspectFile(path string) error {
	f, err := c.ctx.ref(path)
	if err != nil {
		c.ctx.RecordError(path, "hash", err)
		return nil
	}
	if !f.IsRegular() || !c.rule.Match(f, c.ctx.Env) {
		return nil
	}
	// Register interest only. The broker opens the file once, after every
	// collector has been asked, so hashing and copying share a single read.
	c.ctx.Broker.Want(c.rule.ID, func(ct content.Content) error {
		return c.digest(f, ct)
	})
	return nil
}

func (c *hashCollector) algos() []string {
	if len(c.algorithms) == 0 {
		c.algorithms = c.ctx.Env.HashAlgorithm
		if len(c.algorithms) == 0 {
			// UAC's shipped default. Not sha256: the differential harness
			// caught that assumption.
			c.algorithms = []string{"md5", "sha1"}
		}
	}
	return c.algorithms
}

func (c *hashCollector) digest(f *fsref.FileRef, ct content.Content) error {
	algos := c.algos()
	hashes := make([]hash.Hash, 0, len(algos))
	sinks := make([]io.Writer, 0, len(algos))
	for _, a := range algos {
		var h hash.Hash
		switch a {
		case "md5":
			h = md5.New()
		case "sha1":
			h = sha1.New()
		case "sha256":
			h = sha256.New()
		default:
			continue
		}
		hashes = append(hashes, h)
		sinks = append(sinks, h)
	}
	if len(hashes) == 0 {
		return nil
	}
	// One pass over the bytes feeds every digest.
	if buf, ok := ct.Bytes(); ok {
		for _, h := range hashes {
			h.Write(buf)
		}
	} else if _, err := io.Copy(io.MultiWriter(sinks...), ct.Reader()); err != nil {
		return err
	}

	if c.writers == nil {
		c.writers = map[string]*spool.Writer{}
	}
	name := c.rule.OutputFile
	if name == "" {
		name = "hashes"
	}
	for i, a := range algos {
		w, ok := c.writers[a]
		if !ok {
			var err error
			w, err = c.ctx.Store.Open(c.rule.ID, "hashes", c.rule.OutputDir, name+"."+a)
			if err != nil {
				return err
			}
			c.writers[a] = w
		}
		// Two spaces before the path, matching md5sum/sha1sum output, which is
		// what UAC's hash collector produces.
		if err := w.Writef("%s  %s", hex.EncodeToString(hashes[i].Sum(nil)), f.Path); err != nil {
			return err
		}
	}
	return nil
}

func (c *hashCollector) Flush() error {
	for _, w := range c.writers {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func (c *hashCollector) ScanResults() (any, error) {
	return func(yield func(Result, error) bool) {
		for _, e := range c.ctx.Store.Manifest() {
			if e.Collector != c.rule.ID {
				continue
			}
			for line, err := range spool.Lines(e.Path) {
				if !yield(Result{Collector: c.rule.ID, Line: line}, err) {
					return
				}
			}
		}
	}, nil
}

// ---------------------------------------------------------------------------
// file: copy bytes into the output tree
// ---------------------------------------------------------------------------

type fileCollector struct {
	base
	// seen deduplicates hardlinks by (device, inode): a file with many links
	// is stored once, not once per link.
	seen map[[2]uint64]string
}

func (c *fileCollector) InspectFile(path string) error {
	f, err := c.ctx.ref(path)
	if err != nil {
		c.ctx.RecordError(path, "file", err)
		return nil
	}
	// UAC copies the find output and then drops everything that is not a
	// regular file, so directories and specials never reach the output tree.
	if !f.IsRegular() || !c.rule.Match(f, c.ctx.Env) {
		return nil
	}
	if c.seen == nil {
		c.seen = map[[2]uint64]string{}
	}
	key := [2]uint64{f.Dev, f.Ino}
	if _, dup := c.seen[key]; dup && f.Nlink > 1 {
		return nil
	}
	c.seen[key] = f.Path

	c.ctx.Broker.Want(c.rule.ID, func(ct content.Content) error {
		return c.copy(f, ct)
	})
	return nil
}

func (c *fileCollector) copy(f *fsref.FileRef, ct content.Content) error {
	dst := filepath.Join(c.ctx.OutputRoot, "[root]", strings.TrimPrefix(f.Path, "/"))
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	if buf, ok := ct.Bytes(); ok {
		if _, err := out.Write(buf); err != nil {
			return err
		}
	} else if _, err := io.Copy(out, ct.Reader()); err != nil {
		return err
	}
	w, err := c.writer("copies", "file_collector.txt")
	if err != nil {
		return err
	}
	return w.WriteLine(f.Path)
}

func (c *fileCollector) ScanResults() (any, error) { return c.stream(), nil }

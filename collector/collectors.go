package collector

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"uacscan/internal/content"
	"uacscan/internal/fileattr"
	"uacscan/internal/fsref"
	"uacscan/internal/rules"
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
	// The two find artifacts that pipe results through a command become native
	// per-file work, and reproduce the tool's output rather than just the path.
	line := f.Path
	switch {
	case strings.HasPrefix(c.rule.Command, "getcap"):
		attr, err := getxattr(f.Real, "security.capability")
		if err != nil {
			return nil // no capability set: not an error, just not a match
		}
		text, err := fileattr.Capabilities(attr)
		if err != nil {
			return nil
		}
		// getcap prints "<path> <capabilities>".
		line = f.Path + " " + text

	case strings.Contains(c.rule.Command, "lsattr"):
		// statx answers "is it immutable" without opening anything, so the
		// descriptor GetFlags needs is only opened for the few files that are.
		set, known := f.Immutable()
		if !known {
			c.ctx.RecordError(path, "immutable",
				fmt.Errorf("filesystem does not report the immutable attribute"))
			return nil
		}
		if !set {
			return nil
		}
		flags, err := fileattr.GetFlags(f.Real)
		if err != nil {
			c.ctx.RecordError(path, "lsattr", err)
			return nil
		}
		// lsattr prints "<flags> <path>", which is what UAC's awk filters on.
		line = fileattr.FlagString(flags) + " " + f.Path
	}
	w, err := c.writer("paths", "find.txt")
	if err != nil {
		return err
	}
	return w.WriteLine(line)
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

// digester pairs an algorithm name with its hash, so that skipping an
// unsupported name cannot leave the two lists at different lengths.
type digester struct {
	name string
	h    hash.Hash
}

func newDigest(name string) (hash.Hash, bool) {
	switch name {
	case "md5":
		return md5.New(), true
	case "sha1":
		return sha1.New(), true
	case "sha256":
		return sha256.New(), true
	}
	return nil, false
}

func (c *hashCollector) digest(f *fsref.FileRef, ct content.Content) error {
	var (
		digests []digester
		sinks   []io.Writer
	)
	for _, a := range c.algos() {
		h, ok := newDigest(a)
		if !ok {
			continue
		}
		digests = append(digests, digester{name: a, h: h})
		sinks = append(sinks, h)
	}
	if len(digests) == 0 {
		return nil
	}
	// One pass over the bytes feeds every digest.
	if buf, ok := ct.Bytes(); ok {
		for _, d := range digests {
			d.h.Write(buf)
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
	for _, d := range digests {
		w, ok := c.writers[d.name]
		if !ok {
			var err error
			w, err = c.ctx.Store.Open(c.rule.ID, "hashes", c.rule.OutputDir, name+"."+d.name)
			if err != nil {
				return content.Fatal(err)
			}
			c.writers[d.name] = w
		}
		// Two spaces before the path, matching md5sum/sha1sum output, which is
		// what UAC's hash collector produces.
		if err := w.Writef("%s  %s", hex.EncodeToString(d.h.Sum(nil)), f.Path); err != nil {
			return content.Fatal(err)
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
	// The destination is built from the same image-controlled path as the
	// source, so it needs the same containment check.
	dst, err := fsref.DestinationUnder(filepath.Join(c.ctx.OutputRoot, "[root]"), f.Path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return content.Fatal(err)
	}
	// O_NOFOLLOW: a symlink sitting at the destination must not redirect
	// collected evidence somewhere else.
	out, err := fsref.CreateNoFollow(dst, 0644)
	if err != nil {
		return content.Fatal(err)
	}
	defer out.Close()
	if buf, ok := ct.Bytes(); ok {
		if _, err := out.Write(buf); err != nil {
			return content.Fatal(err)
		}
	} else if _, err := io.Copy(out, ct.Reader()); err != nil {
		// A copy can fail either end. A read error is the source's problem and
		// is recoverable; anything else means the destination.
		if isSourceReadError(err) {
			return err
		}
		return content.Fatal(err)
	}
	if err := out.Close(); err != nil {
		return content.Fatal(err)
	}
	w, err := c.writer("copies", "file_collector.txt")
	if err != nil {
		return content.Fatal(err)
	}
	return content.Fatal(w.WriteLine(f.Path))
}

// Finish collects the second phase of a two-phase artifact: the paths a list
// producer discovered while the walk was running.
//
// This is not a second traversal. The list names specific files, so each is
// resolved and copied directly -- a handful of stats, not another pass over the
// tree.
func (c *fileCollector) Finish() error {
	if !c.rule.FromList {
		return nil
	}
	for _, p := range c.ctx.List(c.rule.ListKey) {
		// The path came out of a file's contents, so it is only as trustworthy
		// as the image. ResolveBeneath refuses one that would leave the mount,
		// including by way of a symlinked directory component.
		f, err := fsref.ResolveBeneath(c.ctx.Env.MountPoint, p)
		if err != nil {
			// A shell configured a history file that does not exist. Worth
			// recording -- it is evidence about configuration -- but not an
			// error that should stop anything.
			c.ctx.RecordError(p, "file_list", err)
			continue
		}
		if !f.IsRegular() {
			continue
		}
		if c.seen == nil {
			c.seen = map[[2]uint64]string{}
		}
		key := [2]uint64{f.Dev, f.Ino}
		if _, dup := c.seen[key]; dup {
			continue
		}
		c.seen[key] = f.Path

		c.ctx.Broker.Want(c.rule.ID, func(ct content.Content) error {
			return c.copy(f, ct)
		})
		if err := c.ctx.Broker.Run(f); err != nil {
			return err
		}
	}
	return nil
}

func (c *fileCollector) ScanResults() (any, error) { return c.stream(), nil }

// ---------------------------------------------------------------------------
// list: the producing half of a two-phase artifact
// ---------------------------------------------------------------------------

// listCollector reads a shell's rc files during the walk and records the
// history file paths they name, for an is_file_list rule to collect afterwards.
type listCollector struct{ base }

func (c *listCollector) InspectFile(path string) error {
	f, err := c.ctx.ref(path)
	if err != nil {
		c.ctx.RecordError(path, "list", err)
		return nil
	}
	if !f.IsRegular() || !c.rule.Match(f, c.ctx.Env) {
		return nil
	}
	c.ctx.Broker.Want(c.rule.ID, func(ct content.Content) error {
		return c.harvest(f, ct)
	})
	return nil
}

func (c *listCollector) harvest(f *fsref.FileRef, ct content.Content) error {
	buf, ok := ct.Bytes()
	if !ok {
		// An rc file large enough to miss the buffer threshold is not a shell
		// rc file in any real sense, but read it rather than guess.
		b, err := io.ReadAll(ct.Reader())
		if err != nil {
			return err
		}
		buf = b
	}
	for _, value := range c.rule.Histfile.ExtractAssignments(buf) {
		// A "~/" in a per-user rc file means that user's home, which the path
		// tells us. In a system-wide rc file it means whichever user is being
		// considered, so it has to fan out across every home.
		for _, home := range c.homesFor(f.Path) {
			if resolved, ok := rules.ResolveHistfile(value, home); ok {
				c.ctx.AddToList(c.rule.ListKey, resolved)
			} else if !strings.HasPrefix(value, "~") {
				c.ctx.RecordError(f.Path, "histfile",
					fmt.Errorf("cannot resolve %s=%q to an absolute path", c.rule.Histfile.Var, value))
			}
		}
	}
	return nil
}

// homesFor returns the home directories a "~/" in this file could refer to.
func (c *listCollector) homesFor(path string) []string {
	var best string
	for _, h := range c.rule.Homes {
		if strings.HasPrefix(path, strings.TrimSuffix(h, "/")+"/") && len(h) > len(best) {
			best = h
		}
	}
	if best != "" {
		return []string{best}
	}
	if len(c.rule.Homes) == 0 {
		return []string{""}
	}
	return c.rule.Homes
}

func (c *listCollector) ScanResults() (any, error) {
	key := c.rule.ListKey
	return func(yield func(Result, error) bool) {
		for _, p := range c.ctx.List(key) {
			if !yield(Result{Collector: c.rule.ID, Line: p}, nil) {
				return
			}
		}
	}, nil
}

// isSourceReadError reports whether a copy failure came from reading the
// evidence rather than from writing the output.
//
// The distinction decides whether the scan continues. A bad sector or an
// unreadable file is the image's problem and is recorded; anything else during
// a copy means the destination could not be written, which compromises the
// acquisition and must stop it.
func isSourceReadError(err error) bool {
	return errors.Is(err, syscall.EIO) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPERM) ||
		errors.Is(err, content.ErrExpired)
}

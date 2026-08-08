// Package content opens a matched file once and shares it with every collector
// that asked for its bytes.
//
// Two things drive the design. First, collectors must never receive a raw
// descriptor: a file offset is shared state, so the second collector to call
// Read would see an empty file, and a third-party collector that closes the
// descriptor causes the number to be recycled -- after which a retained
// reference silently reads a *different* file into the evidence output. What
// collectors get instead is a revocable, read-only view with per-caller
// offsets.
//
// Second, measurement: for a typical forensic artifact, reading the whole file
// into a reusable buffer costs the same as a single streaming pass, but also
// gives every collector independent random access. So small files are buffered
// and large ones stay on the descriptor.
package content

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"syscall"

	"uacscan/internal/fsref"
)

// DefaultBufferLimit is the size below which a file is read into memory. One
// buffer is reused for the whole walk, so this is the peak, not per file.
const DefaultBufferLimit = 4 << 20

// ErrExpired is returned when a collector uses a view after the walker has
// moved on. Failing loudly beats reading whatever file inherited the fd.
var ErrExpired = errors.New("content: view used after the walker moved to the next file")

// FatalError marks a failure that must stop the scan.
//
// The two kinds of failure are not alike. Failing to *read* a source file is
// routine on a real image -- a bad sector, a permission denial -- and must not
// abort an acquisition. Failing to *write* output is not routine: the disk is
// full, the destination is unwritable, the spool cannot be appended to. Left as
// a recorded error, that produces a partial acquisition that exits zero and
// looks complete, which is the worst outcome this tool can have.
type FatalError struct{ Err error }

func (e *FatalError) Error() string { return "output failed: " + e.Err.Error() }
func (e *FatalError) Unwrap() error { return e.Err }

// Fatal wraps an error as unrecoverable.
func Fatal(err error) error {
	if err == nil {
		return nil
	}
	return &FatalError{Err: err}
}

// IsFatal reports whether an error must stop the scan.
func IsFatal(err error) bool {
	var f *FatalError
	return errors.As(err, &f)
}

// Content is the read-only, offset-free handle collectors receive.
type Content interface {
	// Path is the image-relative path, for error messages and records.
	Path() string
	Size() int64
	// ReadAt has no shared offset: two collectors can read concurrently and
	// independently.
	ReadAt(p []byte, off int64) (int, error)
	// Reader returns a fresh independent stream over the whole file.
	Reader() io.Reader
	// Bytes returns the buffered contents when the file was small enough to
	// hold in memory, avoiding a copy for the common case.
	Bytes() ([]byte, bool)
}

// Consumer is a collector's request for file bytes, registered during the
// metadata phase and run once the file is open.
type Consumer struct {
	Name string
	Fn   func(Content) error
}

// Broker collects requests for one file and then serves them from a single
// open. Requests are registered while rules are being evaluated; Run performs
// the open, and nothing is opened at all if nobody asked.
type Broker struct {
	BufferLimit int64

	pending []Consumer
	buf     []byte

	// OnError receives per-consumer failures. A collector that cannot read a
	// file must not abort the walk -- unreadable files are routine on real
	// images -- so these are recorded, not returned.
	OnError func(path, consumer string, err error)
}

func NewBroker() *Broker {
	return &Broker{BufferLimit: DefaultBufferLimit}
}

// Want registers interest in the current file's bytes.
func (b *Broker) Want(name string, fn func(Content) error) {
	b.pending = append(b.pending, Consumer{Name: name, Fn: fn})
}

// Wanted reports whether anything asked for this file.
func (b *Broker) Wanted() bool { return len(b.pending) > 0 }

// Reset drops any pending requests without serving them.
func (b *Broker) Reset() { b.pending = b.pending[:0] }

// Run opens the file once, hands a view to every registered consumer in
// registration order, then revokes the view and closes the descriptor.
//
// The open is deliberately the *last* thing to happen: it only occurs after a
// rule matched, so device nodes found in a mounted image are never opened. On
// an image mounted without nodev they would resolve to the examiner's own
// hardware.
func (b *Broker) Run(f *fsref.FileRef) error {
	if len(b.pending) == 0 {
		return nil
	}
	defer b.Reset()

	// Only regular files have bytes worth reading. Refusing everything else
	// also removes any chance of blocking on a FIFO or touching a device.
	if !f.IsRegular() {
		for _, c := range b.pending {
			b.reportErr(f.Path, c.Name, fmt.Errorf("not a regular file"))
		}
		return nil
	}

	fd, err := syscall.Open(f.Real,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		for _, c := range b.pending {
			b.reportErr(f.Path, c.Name, err)
		}
		return nil
	}
	fh := os.NewFile(uintptr(fd), f.Real)
	defer fh.Close()

	var view Content
	var revoke func()

	if f.Size >= 0 && f.Size <= b.bufferLimit() {
		if int64(cap(b.buf)) < f.Size {
			b.buf = make([]byte, f.Size)
		}
		buf := b.buf[:f.Size]
		n, rerr := io.ReadFull(fh, buf)
		if rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) && !errors.Is(rerr, io.EOF) {
			for _, c := range b.pending {
				b.reportErr(f.Path, c.Name, rerr)
			}
			return nil
		}
		bv := &bufferView{path: f.Path, buf: buf[:n]}
		view, revoke = bv, bv.revoke
	} else {
		fv := &fdView{path: f.Path, f: fh, size: f.Size}
		view, revoke = fv, fv.revoke
	}
	defer revoke()

	for _, c := range b.pending {
		if err := c.Fn(view); err != nil {
			// A consumer that could not write its output has not merely failed
			// on this file; the acquisition is compromised and must stop.
			if IsFatal(err) {
				return fmt.Errorf("%s: %w", f.Path, err)
			}
			b.reportErr(f.Path, c.Name, err)
		}
	}
	return nil
}

func (b *Broker) bufferLimit() int64 {
	if b.BufferLimit <= 0 {
		return DefaultBufferLimit
	}
	return b.BufferLimit
}

func (b *Broker) reportErr(path, consumer string, err error) {
	if b.OnError != nil {
		b.OnError(path, consumer, err)
	}
}

// bufferView serves a fully buffered small file.
type bufferView struct {
	path string
	buf  []byte
	dead atomic.Bool
}

func (v *bufferView) revoke()      { v.dead.Store(true) }
func (v *bufferView) Path() string { return v.path }
func (v *bufferView) Size() int64  { return int64(len(v.buf)) }

func (v *bufferView) ReadAt(p []byte, off int64) (int, error) {
	if v.dead.Load() {
		return 0, ErrExpired
	}
	if off < 0 || off > int64(len(v.buf)) {
		return 0, io.EOF
	}
	n := copy(p, v.buf[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (v *bufferView) Reader() io.Reader { return io.NewSectionReader(v, 0, v.Size()) }

func (v *bufferView) Bytes() ([]byte, bool) {
	if v.dead.Load() {
		return nil, false
	}
	return v.buf, true
}

// fdView serves a large file straight off the descriptor. Every caller gets its
// own offset via ReadAt, so consumers cannot disturb each other.
type fdView struct {
	path string
	f    *os.File
	size int64
	dead atomic.Bool
}

func (v *fdView) revoke()      { v.dead.Store(true) }
func (v *fdView) Path() string { return v.path }
func (v *fdView) Size() int64  { return v.size }

func (v *fdView) ReadAt(p []byte, off int64) (int, error) {
	if v.dead.Load() {
		return 0, ErrExpired
	}
	return v.f.ReadAt(p, off)
}

func (v *fdView) Reader() io.Reader { return io.NewSectionReader(v, 0, v.size) }

func (v *fdView) Bytes() ([]byte, bool) { return nil, false }

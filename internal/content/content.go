// Package content opens a matched file once and shares it with every collector
// that asked for its bytes.
//
// Three things drive the design.
//
// First, collectors must never receive a raw descriptor: a file offset is
// shared state, so the second collector to call Read would see an empty file,
// and a third-party collector that closes the descriptor causes the number to
// be recycled -- after which a retained reference silently reads a *different*
// file into the evidence output. What collectors get instead is a revocable,
// read-only view with per-caller offsets.
//
// Second, measurement: for a typical forensic artifact, reading the whole file
// into a reusable buffer costs the same as a single streaming pass, but also
// gives every collector independent random access. So small files are buffered
// and large ones stay on the descriptor.
//
// Third, the content phase is where a real acquisition spends most of its time
// -- measured at 44% of a warm scan, and the overwhelming majority of a cold
// one, because a single thread waits for each open/read/write to complete
// before starting the next. So the bulk work runs on a bounded pool of
// workers. The walker itself stays single-threaded, which is what preserves
// the one-entry stat cache and deterministic rule evaluation.
//
// Parallelism must not change what a collection contains or what order it is
// written in: two runs of the same image have to be diffable, and an examiner
// comparing against a colleague's run should not see reordered evidence. So
// each consumer splits in two. The bulk -- reading, hashing, copying bytes --
// happens in the worker. The tail that appends a line to an output file is
// handed to Emit, and a single sequencer goroutine runs those tails strictly
// in walk order. Output is therefore byte-identical to a serial run, which
// TestParallelOutputMatchesSerial asserts directly.
package content

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"uacscan/internal/fsref"
)

// DefaultBufferLimit is the size below which a file is read into memory.
// Buffers are pooled, so the peak is roughly this times the worker count.
const DefaultBufferLimit = 4 << 20

// ErrExpired is returned when a collector uses a view after the worker that
// owned it has finished. Failing loudly beats reading whatever file inherited
// the descriptor, or whatever the buffer pool handed out next.
var ErrExpired = errors.New("content: view used after the file was released")

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
	//
	// The slice is only valid until the consumer returns: it belongs to a pool
	// and will be handed to another file afterwards. Retaining it is the one
	// mistake the revocation flag cannot catch, because the slice header has
	// already been copied out.
	Bytes() ([]byte, bool)
	// Emit defers a small piece of work -- in practice appending one line to an
	// output file -- until every earlier file's deferred work has run.
	//
	// This is what keeps parallel output byte-identical to serial output. Do
	// the bulk in the consumer, where it runs concurrently with other files,
	// and register only the ordered tail here. The closure runs on a single
	// sequencer goroutine, so it also needs no locking of its own.
	Emit(fn func() error)
}

// Consumer is a collector's request for file bytes, registered during the
// metadata phase and run once the file is open.
type Consumer struct {
	Name string
	Fn   func(Content) error
}

// deferredErr is a per-file problem recorded in a worker and reported in walk
// order, so that the errors log is as reproducible as the evidence.
type deferredErr struct {
	path     string
	consumer string
	err      error
}

// job is one file's content work.
type job struct {
	seq       uint64
	ref       *fsref.FileRef
	consumers []Consumer

	// Filled in by the worker, consumed by the sequencer.
	emits    []func() error
	deferred []deferredErr
	fatal    error
}

// Broker collects requests for one file and then serves them from a single
// open. Requests are registered while rules are being evaluated; Run performs
// the open, and nothing is opened at all if nobody asked.
type Broker struct {
	// BufferLimit is the size below which a file is read whole.
	BufferLimit int64

	// Workers is the number of files whose content is processed concurrently.
	// Zero or one keeps everything on the calling goroutine, which is what the
	// unit tests use and what makes a failure easy to read in a stack trace.
	Workers int

	pending []Consumer

	// OnError receives per-file failures. A collector that cannot read a file
	// must not abort the walk -- unreadable files are routine on real images --
	// so these are recorded, not returned. It is called only from the sequencer
	// goroutine, so implementations need no locking and see files in walk
	// order.
	OnError func(path, consumer string, err error)

	jobs chan *job
	done chan *job
	seq  uint64

	workerWG sync.WaitGroup
	seqWG    sync.WaitGroup

	fatalMu sync.Mutex
	fatal   error

	bufPool sync.Pool
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

// Run serves the registered consumers for one file.
//
// With a single worker everything happens inline. With more, the file is
// queued and Run returns as soon as the queue has room, so the walker carries
// on stat'ing while workers read. The error it returns is therefore not
// necessarily about *this* file: it is the first fatal output failure seen so
// far, which is what stops the walk.
//
// The open is deliberately the last thing to happen, and happens in the
// worker: it only occurs after a rule matched, so device nodes found in a
// mounted image are never opened. On an image mounted without nodev they would
// resolve to the examiner's own hardware.
func (b *Broker) Run(f *fsref.FileRef) error {
	if len(b.pending) == 0 {
		return b.Err()
	}
	consumers := make([]Consumer, len(b.pending))
	copy(consumers, b.pending)
	b.Reset()

	if b.workers() <= 1 {
		j := &job{ref: f, consumers: consumers}
		b.process(j)
		b.apply(j)
		return b.Err()
	}

	b.startPool()
	// Stop feeding the pool the moment an output failure is known, rather than
	// queueing thousands more files that will never be written.
	if err := b.Err(); err != nil {
		return err
	}
	j := &job{seq: b.seq, ref: f, consumers: consumers}
	b.seq++
	b.jobs <- j
	return nil
}

// Wait blocks until all queued content work has completed and its output has
// been written. It must be called before the results are read.
//
// It is safe to call more than once, and to enqueue further work afterwards:
// the two-phase artifacts collect their files after the walk proper has
// finished.
func (b *Broker) Wait() error {
	if b.jobs != nil {
		close(b.jobs)
		b.workerWG.Wait()
		close(b.done)
		b.seqWG.Wait()
		b.jobs, b.done = nil, nil
	}
	return b.Err()
}

// Err returns the first fatal output failure, if any.
func (b *Broker) Err() error {
	b.fatalMu.Lock()
	defer b.fatalMu.Unlock()
	return b.fatal
}

func (b *Broker) setFatal(err error) {
	b.fatalMu.Lock()
	defer b.fatalMu.Unlock()
	if b.fatal == nil {
		b.fatal = err
	}
}

func (b *Broker) workers() int {
	if b.Workers <= 0 {
		return 1
	}
	return b.Workers
}

func (b *Broker) startPool() {
	if b.jobs != nil {
		return
	}
	n := b.workers()
	// Enough slack that a single large file does not stall the walker, but
	// bounded so that queued work cannot grow without limit: the walker blocks
	// on a full queue, which is the backpressure that keeps memory flat.
	b.jobs = make(chan *job, n*4)
	b.done = make(chan *job, n*4)

	b.workerWG.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer b.workerWG.Done()
			for j := range b.jobs {
				b.process(j)
				b.done <- j
			}
		}()
	}

	b.seqWG.Add(1)
	go func() {
		defer b.seqWG.Done()
		b.sequence()
	}()
}

// sequence applies each job's deferred output in walk order.
//
// Workers finish in whatever order the filesystem and scheduler produce, so
// completed jobs are held until their turn comes. The reorder buffer is
// bounded by the number of jobs in flight, which the queue capacity caps.
func (b *Broker) sequence() {
	held := map[uint64]*job{}
	next := uint64(0)
	for j := range b.done {
		held[j.seq] = j
		for {
			ready, ok := held[next]
			if !ok {
				break
			}
			delete(held, next)
			b.apply(ready)
			next++
		}
	}
	// Any jobs still held after the channel closes would mean a gap in the
	// sequence, which cannot happen -- every enqueued job is returned exactly
	// once -- but draining them keeps a bug from silently losing evidence.
	for len(held) > 0 {
		ready, ok := held[next]
		if ok {
			delete(held, next)
			b.apply(ready)
		}
		next++
	}
}

// apply runs one job's ordered tail: recorded errors first, then emits.
// Always on a single goroutine, so collector state touched here needs no
// locking.
func (b *Broker) apply(j *job) {
	for _, d := range j.deferred {
		if b.OnError != nil {
			b.OnError(d.path, d.consumer, d.err)
		}
	}
	if j.fatal != nil {
		b.setFatal(j.fatal)
		return
	}
	for _, fn := range j.emits {
		if err := fn(); err != nil {
			if IsFatal(err) {
				b.setFatal(fmt.Errorf("%s: %w", j.ref.Path, err))
				return
			}
			if b.OnError != nil {
				b.OnError(j.ref.Path, "emit", err)
			}
		}
	}
}

// process does one file's bulk work: open, read, and run every consumer.
// Runs on a worker goroutine when the pool is active.
func (b *Broker) process(j *job) {
	f := j.ref

	// Only regular files have bytes worth reading. Refusing everything else
	// also removes any chance of blocking on a FIFO or touching a device.
	if !f.IsRegular() {
		j.deferAll(f.Path, fmt.Errorf("not a regular file"))
		return
	}

	fd, err := syscall.Open(f.Real,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		j.deferAll(f.Path, err)
		return
	}
	fh := os.NewFile(uintptr(fd), f.Real)
	defer fh.Close()

	var (
		view Content
		core *viewCore
	)
	if f.Size >= 0 && f.Size <= b.bufferLimit() {
		bufp := b.getBuf()
		defer b.putBuf(bufp)

		buf := (*bufp)[:f.Size]
		n, rerr := io.ReadFull(fh, buf)
		if rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) && !errors.Is(rerr, io.EOF) {
			j.deferAll(f.Path, rerr)
			return
		}
		bv := &bufferView{viewCore: viewCore{path: f.Path}, buf: buf[:n]}
		view, core = bv, &bv.viewCore
	} else {
		fv := &fdView{viewCore: viewCore{path: f.Path}, f: fh, size: f.Size}
		view, core = fv, &fv.viewCore
	}

	for _, c := range j.consumers {
		if err := c.Fn(view); err != nil {
			// A consumer that could not write its output has not merely failed
			// on this file; the acquisition is compromised and must stop.
			if IsFatal(err) {
				j.fatal = fmt.Errorf("%s: %w", f.Path, err)
				break
			}
			j.deferred = append(j.deferred, deferredErr{f.Path, c.Name, err})
		}
	}

	// Revoke before the tail runs: the descriptor is about to close and the
	// buffer is about to go back to the pool, so a retained view must fail
	// from here on rather than read another file's bytes.
	core.revoke()
	j.emits = core.emits
}

func (j *job) deferAll(path string, err error) {
	for _, c := range j.consumers {
		j.deferred = append(j.deferred, deferredErr{path, c.Name, err})
	}
}

func (b *Broker) bufferLimit() int64 {
	if b.BufferLimit <= 0 {
		return DefaultBufferLimit
	}
	return b.BufferLimit
}

func (b *Broker) getBuf() *[]byte {
	if v := b.bufPool.Get(); v != nil {
		return v.(*[]byte)
	}
	buf := make([]byte, b.bufferLimit())
	return &buf
}

func (b *Broker) putBuf(p *[]byte) {
	if int64(cap(*p)) >= b.bufferLimit() {
		*p = (*p)[:cap(*p)]
		b.bufPool.Put(p)
	}
}

// viewCore is the part of a view that does not depend on where the bytes live.
type viewCore struct {
	path  string
	dead  atomic.Bool
	emits []func() error
}

func (v *viewCore) Path() string         { return v.path }
func (v *viewCore) Emit(fn func() error) { v.emits = append(v.emits, fn) }
func (v *viewCore) revoke()              { v.dead.Store(true) }
func (v *viewCore) expired() bool        { return v.dead.Load() }

// bufferView serves a fully buffered small file.
type bufferView struct {
	viewCore
	buf []byte
}

func (v *bufferView) Size() int64 { return int64(len(v.buf)) }

func (v *bufferView) ReadAt(p []byte, off int64) (int, error) {
	if v.expired() {
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
	if v.expired() {
		return nil, false
	}
	return v.buf, true
}

// fdView serves a large file straight off the descriptor. Every caller gets its
// own offset via ReadAt, so consumers cannot disturb each other.
type fdView struct {
	viewCore
	f    *os.File
	size int64
}

func (v *fdView) Size() int64 { return v.size }

func (v *fdView) ReadAt(p []byte, off int64) (int, error) {
	if v.expired() {
		return 0, ErrExpired
	}
	return v.f.ReadAt(p, off)
}

func (v *fdView) Reader() io.Reader { return io.NewSectionReader(v, 0, v.size) }

func (v *fdView) Bytes() ([]byte, bool) { return nil, false }

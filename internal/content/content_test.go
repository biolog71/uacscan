package content

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"uacscan/internal/fsref"
)

func mkfile(t *testing.T, dir, name string, data []byte) *fsref.FileRef {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
	ref, err := fsref.Resolve(p, "/"+name, 1)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

// The bug the whole design exists to prevent: with a shared descriptor the
// second consumer sees an empty file.
func TestEveryConsumerSeesTheWholeFile(t *testing.T) {
	dir := t.TempDir()
	data := []byte("the quick brown fox")
	ref := mkfile(t, dir, "f", data)

	for _, limit := range []int64{DefaultBufferLimit, 1} { // buffered, then fd-backed
		b := NewBroker()
		b.BufferLimit = limit
		got := make([][]byte, 3)
		for i := range got {
			i := i
			b.Want("c", func(c Content) error {
				out, err := io.ReadAll(c.Reader())
				got[i] = out
				return err
			})
		}
		if err := b.Run(ref); err != nil {
			t.Fatal(err)
		}
		for i, g := range got {
			if !bytes.Equal(g, data) {
				t.Errorf("limit=%d consumer %d got %q, want %q", limit, i, g, data)
			}
		}
	}
}

func TestConsumersHaveIndependentOffsets(t *testing.T) {
	dir := t.TempDir()
	ref := mkfile(t, dir, "f", []byte("0123456789"))
	b := NewBroker()
	b.BufferLimit = 1 // force the fd path, where a shared offset would bite

	var first, second []byte
	b.Want("a", func(c Content) error {
		buf := make([]byte, 4)
		n, _ := c.ReadAt(buf, 0)
		first = append([]byte(nil), buf[:n]...)
		return nil
	})
	b.Want("b", func(c Content) error {
		buf := make([]byte, 4)
		n, _ := c.ReadAt(buf, 0)
		second = append([]byte(nil), buf[:n]...)
		return nil
	})
	if err := b.Run(ref); err != nil {
		t.Fatal(err)
	}
	if string(first) != "0123" || string(second) != "0123" {
		t.Errorf("offsets not independent: first=%q second=%q", first, second)
	}
}

func TestViewIsRevokedAfterRun(t *testing.T) {
	dir := t.TempDir()
	ref := mkfile(t, dir, "f", []byte("data"))

	for _, limit := range []int64{DefaultBufferLimit, 1} {
		b := NewBroker()
		b.BufferLimit = limit
		var retained Content
		b.Want("hoarder", func(c Content) error {
			retained = c // a badly behaved collector keeps the handle
			return nil
		})
		if err := b.Run(ref); err != nil {
			t.Fatal(err)
		}
		if _, err := retained.ReadAt(make([]byte, 4), 0); !errors.Is(err, ErrExpired) {
			t.Errorf("limit=%d: retained view returned %v, want ErrExpired", limit, err)
		}
		if _, ok := retained.Bytes(); ok {
			t.Errorf("limit=%d: revoked view still handed out its buffer", limit)
		}
	}
}

func TestNothingIsOpenedWhenNobodyAsks(t *testing.T) {
	dir := t.TempDir()
	ref := mkfile(t, dir, "f", []byte("x"))
	b := NewBroker()
	if b.Wanted() {
		t.Fatal("broker reports pending work with no requests")
	}
	if err := b.Run(ref); err != nil {
		t.Fatal(err)
	}
}

// Opening a FIFO would block; the broker must refuse non-regular files outright
// rather than relying on O_NONBLOCK to save it.
func TestNonRegularFilesAreRefused(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(p, 0644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	ref, err := fsref.Resolve(p, "/fifo", 1)
	if err != nil {
		t.Fatal(err)
	}
	b := NewBroker()
	var errs []string
	b.OnError = func(path, consumer string, err error) {
		errs = append(errs, path+":"+consumer+":"+err.Error())
	}
	called := false
	b.Want("greedy", func(c Content) error { called = true; return nil })
	if err := b.Run(ref); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("consumer was handed a FIFO")
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "not a regular file") {
		t.Errorf("expected a recorded error, got %v", errs)
	}
}

// An unreadable file is routine on a real image and must not abort the walk.
func TestUnreadableFileIsRecordedNotFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permissions do not apply")
	}
	dir := t.TempDir()
	ref := mkfile(t, dir, "secret", []byte("x"))
	if err := os.Chmod(ref.Real, 0000); err != nil {
		t.Fatal(err)
	}
	b := NewBroker()
	var got error
	b.OnError = func(path, consumer string, err error) { got = err }
	b.Want("reader", func(c Content) error { return nil })
	if err := b.Run(ref); err != nil {
		t.Fatalf("Run returned a fatal error for an unreadable file: %v", err)
	}
	if got == nil {
		t.Error("permission failure was not recorded")
	}
}

func TestConsumerErrorDoesNotStopOtherConsumers(t *testing.T) {
	dir := t.TempDir()
	ref := mkfile(t, dir, "f", []byte("x"))
	b := NewBroker()
	var recorded []string
	b.OnError = func(path, consumer string, err error) { recorded = append(recorded, consumer) }
	ran := 0
	b.Want("bad", func(c Content) error { return errors.New("boom") })
	b.Want("good", func(c Content) error { ran++; return nil })
	if err := b.Run(ref); err != nil {
		t.Fatal(err)
	}
	if ran != 1 {
		t.Error("a failing consumer prevented the next one from running")
	}
	if len(recorded) != 1 || recorded[0] != "bad" {
		t.Errorf("recorded = %v", recorded)
	}
}

func TestSmallFilesAreBufferedLargeOnesAreNot(t *testing.T) {
	dir := t.TempDir()
	small := mkfile(t, dir, "small", bytes.Repeat([]byte("a"), 10))
	big := mkfile(t, dir, "big", bytes.Repeat([]byte("b"), 100))

	b := NewBroker()
	b.BufferLimit = 50

	var smallBuffered, bigBuffered bool
	b.Want("c", func(c Content) error { _, smallBuffered = c.Bytes(); return nil })
	if err := b.Run(small); err != nil {
		t.Fatal(err)
	}
	b.Want("c", func(c Content) error { _, bigBuffered = c.Bytes(); return nil })
	if err := b.Run(big); err != nil {
		t.Fatal(err)
	}
	if !smallBuffered {
		t.Error("small file was not buffered")
	}
	if bigBuffered {
		t.Error("large file was buffered")
	}
}

func TestBufferIsReusedAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	b := NewBroker()
	var caps []int
	for i := 0; i < 5; i++ {
		ref := mkfile(t, dir, "f", bytes.Repeat([]byte("z"), 1000))
		b.Want("c", func(c Content) error { return nil })
		if err := b.Run(ref); err != nil {
			t.Fatal(err)
		}
		caps = append(caps, cap(b.buf))
	}
	for i := 1; i < len(caps); i++ {
		if caps[i] != caps[0] {
			t.Errorf("buffer reallocated between files: %v", caps)
			break
		}
	}
}

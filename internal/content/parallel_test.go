package content

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"uacscan/internal/fsref"
)

// runOrder collects the order in which emitted tails ran, which is the order
// the output files would be written in.
func runOrder(t *testing.T, workers int, files []string, dir string) []string {
	t.Helper()
	b := NewBroker()
	b.Workers = workers

	var mu sync.Mutex
	var order []string

	for _, name := range files {
		ref, err := fsref.Resolve(filepath.Join(dir, name), "/"+name, 1)
		if err != nil {
			t.Fatal(err)
		}
		b.Want("c", func(c Content) error {
			// Bulk work: read the bytes, exactly as a real consumer would.
			if _, ok := c.Bytes(); !ok {
				if _, err := c.Reader().Read(make([]byte, 1)); err != nil {
					return err
				}
			}
			p := c.Path()
			c.Emit(func() error {
				mu.Lock()
				defer mu.Unlock()
				order = append(order, p)
				return nil
			})
			return nil
		})
		if err := b.Run(ref); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Wait(); err != nil {
		t.Fatal(err)
	}
	return order
}

// The guarantee the whole Emit mechanism exists for: parallel output is
// byte-identical to serial output, so two acquisitions of the same image stay
// diffable no matter how many workers were used.
func TestParallelOutputMatchesSerial(t *testing.T) {
	dir := t.TempDir()

	// Sizes deliberately vary by three orders of magnitude, including some
	// above the buffer limit, so that workers genuinely finish out of order.
	var names []string
	for i := 0; i < 200; i++ {
		name := fmt.Sprintf("f%03d", i)
		size := 1 + (i*7919)%50000
		if i%25 == 0 {
			size = 3 << 20 // large enough to take the streaming path
		}
		if err := os.WriteFile(filepath.Join(dir, name),
			bytes.Repeat([]byte("x"), size), 0644); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}

	serial := runOrder(t, 1, names, dir)
	if len(serial) != len(names) {
		t.Fatalf("serial produced %d results, want %d", len(serial), len(names))
	}
	for _, workers := range []int{2, 4, 8, 16} {
		got := runOrder(t, workers, names, dir)
		if strings.Join(got, "\n") != strings.Join(serial, "\n") {
			t.Errorf("workers=%d produced a different order than serial", workers)
			for i := range got {
				if i < len(serial) && got[i] != serial[i] {
					t.Errorf("  first difference at %d: got %q, serial %q", i, got[i], serial[i])
					break
				}
			}
		}
	}
}

// The bulk of a consumer must actually overlap across files; if it did not,
// the pool would be pure overhead. Blocking every consumer until all of them
// have started can only complete when they run concurrently.
func TestConsumersRunConcurrently(t *testing.T) {
	const workers = 4
	dir := t.TempDir()
	var names []string
	for i := 0; i < workers; i++ {
		name := fmt.Sprintf("f%d", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}

	b := NewBroker()
	b.Workers = workers

	var started sync.WaitGroup
	started.Add(workers)
	release := make(chan struct{})

	for _, name := range names {
		ref, err := fsref.Resolve(filepath.Join(dir, name), "/"+name, 1)
		if err != nil {
			t.Fatal(err)
		}
		b.Want("c", func(c Content) error {
			started.Done()
			<-release // cannot return until every worker is in here at once
			return nil
		})
		if err := b.Run(ref); err != nil {
			t.Fatal(err)
		}
	}

	done := make(chan struct{})
	go func() {
		started.Wait()
		close(release)
		close(done)
	}()

	select {
	case <-done:
	case <-timeoutAfter(t):
		t.Fatal("consumers did not run concurrently; the pool is serialising")
	}
	if err := b.Wait(); err != nil {
		t.Fatal(err)
	}
}

// A fatal output failure has to stop the scan even when it happens on a worker
// several files behind the walker.
func TestFatalFromWorkerStopsTheScan(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 50; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%02d", i)), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	b := NewBroker()
	b.Workers = 4

	var runErr error
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("f%02d", i)
		ref, err := fsref.Resolve(filepath.Join(dir, name), "/"+name, 1)
		if err != nil {
			t.Fatal(err)
		}
		failing := i == 5
		b.Want("c", func(c Content) error {
			if failing {
				return Fatal(fmt.Errorf("disk full"))
			}
			return nil
		})
		if err := b.Run(ref); err != nil {
			runErr = err
			break
		}
	}
	waitErr := b.Wait()

	err := runErr
	if err == nil {
		err = waitErr
	}
	if err == nil {
		t.Fatal("a fatal output failure on a worker did not stop the scan")
	}
	if !IsFatal(err) {
		t.Errorf("error is not marked fatal: %v", err)
	}
	if !strings.Contains(err.Error(), "disk full") {
		t.Errorf("error lost its cause: %v", err)
	}
}

// Per-file read failures stay recoverable under the pool, and are reported in
// walk order rather than completion order.
func TestRecoverableErrorsAreReportedInWalkOrder(t *testing.T) {
	dir := t.TempDir()
	var names []string
	for i := 0; i < 30; i++ {
		name := fmt.Sprintf("f%02d", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}

	b := NewBroker()
	b.Workers = 8
	var reported []string
	b.OnError = func(path, consumer string, err error) {
		reported = append(reported, path) // sequencer-only, so no lock needed
	}

	for _, name := range names {
		ref, err := fsref.Resolve(filepath.Join(dir, name), "/"+name, 1)
		if err != nil {
			t.Fatal(err)
		}
		b.Want("c", func(c Content) error { return fmt.Errorf("boom") })
		if err := b.Run(ref); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Wait(); err != nil {
		t.Fatal(err)
	}

	if len(reported) != len(names) {
		t.Fatalf("got %d errors, want %d", len(reported), len(names))
	}
	for i, name := range names {
		if reported[i] != "/"+name {
			t.Fatalf("errors out of order at %d: got %q, want %q", i, reported[i], "/"+name)
		}
	}
}

// Wait must be safe to call again, because the two-phase artifacts queue more
// content work after the walk proper has finished.
func TestWaitIsReusable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	b := NewBroker()
	b.Workers = 4

	var ran atomic.Int64
	for round := 0; round < 3; round++ {
		ref, err := fsref.Resolve(filepath.Join(dir, "a"), "/a", 1)
		if err != nil {
			t.Fatal(err)
		}
		b.Want("c", func(c Content) error { ran.Add(1); return nil })
		if err := b.Run(ref); err != nil {
			t.Fatal(err)
		}
		if err := b.Wait(); err != nil {
			t.Fatal(err)
		}
		if err := b.Wait(); err != nil { // idempotent
			t.Fatal(err)
		}
	}
	if ran.Load() != 3 {
		t.Errorf("consumer ran %d times, want 3", ran.Load())
	}
}

// A view must not outlive its worker even under the pool: once the file is
// released its buffer goes back to the pool and its descriptor closes.
func TestViewIsRevokedUnderThePool(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	b := NewBroker()
	b.Workers = 4

	var retained Content
	ref, err := fsref.Resolve(filepath.Join(dir, "a"), "/a", 1)
	if err != nil {
		t.Fatal(err)
	}
	b.Want("hoarder", func(c Content) error { retained = c; return nil })
	if err := b.Run(ref); err != nil {
		t.Fatal(err)
	}
	if err := b.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := retained.ReadAt(make([]byte, 4), 0); err != ErrExpired {
		t.Errorf("retained view returned %v, want ErrExpired", err)
	}
	if _, ok := retained.Bytes(); ok {
		t.Error("revoked view still handed out its buffer")
	}
}

// timeoutAfter gives the concurrency tests a bound so a regression that
// serialises the pool fails the test instead of hanging the suite.
func timeoutAfter(t *testing.T) <-chan time.Time {
	t.Helper()
	return time.After(10 * time.Second)
}

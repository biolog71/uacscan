package walk

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"uacscan/internal/uacdata"
)

// Two scans of different images running at the same time must not interfere.
// Run under -race this also proves there is no shared mutable state between
// them, which is the thing that would be invisible in a passing sequential run.
func TestConcurrentScansOfDifferentImages(t *testing.T) {
	const scans = 4

	// Baseline: the same work done one at a time.
	baseline := make([]string, scans)
	for i := range baseline {
		h := setup(t, bodyfileArtifact)
		h.run(t)
		baseline[i] = readBodyfilePaths(t, h.out)
	}

	// Each scan gets its own image, its own output, and its own cache, broker,
	// context and store -- which is what a separate process would have.
	harnesses := make([]*harness, scans)
	for i := range harnesses {
		harnesses[i] = setup(t, bodyfileArtifact)
	}

	var wg sync.WaitGroup
	errs := make([]error, scans)
	for i, h := range harnesses {
		wg.Add(1)
		go func(i int, h *harness) {
			defer wg.Done()
			if err := h.w.Walk(); err != nil {
				errs[i] = err
				return
			}
			errs[i] = h.store.Close()
		}(i, h)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent scan %d failed: %v", i, err)
		}
	}

	// Same inputs, same outputs: concurrency must not change what is collected.
	for i, h := range harnesses {
		got := readBodyfilePaths(t, h.out)
		if got != baseline[i] {
			t.Errorf("scan %d produced different output when run concurrently", i)
		}
	}

	// And the scans must not have written into each other's output.
	for i, h := range harnesses {
		for j, other := range harnesses {
			if i == j {
				continue
			}
			if h.out == other.out {
				t.Fatal("test setup error: scans share an output directory")
			}
		}
	}
}

// The embedded corpus is shared by every scan in a process, so it has to
// tolerate concurrent readers.
func TestConcurrentAccessToTheEmbeddedCorpus(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fsys, err := uacdata.Artifacts()
			if err != nil {
				t.Error(err)
				return
			}
			f, err := fsys.Open("bodyfile/bodyfile.yaml")
			if err != nil {
				t.Error(err)
				return
			}
			defer f.Close()
			buf := make([]byte, 64)
			if _, err := f.Read(buf); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

// A collected file must never be written by two scans at once. Sharing an
// output directory is the one way to break concurrent use, so this documents
// that it is the caller's responsibility rather than something the tool guards.
func TestSeparateOutputDirectoriesDoNotCollide(t *testing.T) {
	a := setup(t, bodyfileArtifact)
	b := setup(t, bodyfileArtifact)
	if a.out == b.out {
		t.Fatal("setup handed two scans the same output directory")
	}

	var wg sync.WaitGroup
	for _, h := range []*harness{a, b} {
		wg.Add(1)
		go func(h *harness) {
			defer wg.Done()
			if err := h.w.Walk(); err != nil {
				t.Error(err)
			}
			h.store.Close()
		}(h)
	}
	wg.Wait()

	for _, h := range []*harness{a, b} {
		fi, err := os.Stat(filepath.Join(h.out, "bodyfile/bodyfile.txt"))
		if err != nil {
			t.Fatalf("missing output: %v", err)
		}
		if fi.Size() == 0 {
			t.Error("output is empty")
		}
	}
}

func readBodyfilePaths(t *testing.T, out string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(out, "bodyfile/bodyfile.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// Inodes and timestamps differ between temp trees; the path column does not.
	var sb []byte
	for _, line := range splitLines(string(b)) {
		fields := splitPipe(line)
		if len(fields) > 1 {
			sb = append(sb, fields[1]...)
			sb = append(sb, '\n')
		}
	}
	return string(sb)
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func splitPipe(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '|' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

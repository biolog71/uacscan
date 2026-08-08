package uacdata

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uacscan/internal/uacpath"
)

func TestEmbeddedCorpusUnpacks(t *testing.T) {
	f, err := FS()
	if err != nil {
		t.Fatal(err)
	}
	var files, yaml int
	if err := fs.WalkDir(f, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		files++
		if strings.HasSuffix(p, ".yaml") {
			yaml++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("embedded: %d files, %d yaml", files, yaml)
	if yaml < 400 {
		t.Errorf("only %d yaml files embedded; expected the full corpus", yaml)
	}
	for _, want := range []string{"VERSION", "config/uac.conf", "artifacts/bodyfile/bodyfile.yaml"} {
		if _, err := fs.ReadFile(f, want); err != nil {
			t.Errorf("missing %s: %v", want, err)
		}
	}
}

func TestArtifactsSubtreeIsRootedLikeACheckout(t *testing.T) {
	a, err := Artifacts()
	if err != nil {
		t.Fatal(err)
	}
	// Paths must read the same as they do from a real checkout, because they
	// become rule ids and appear in the output.
	if _, err := fs.ReadFile(a, "files/system/etc.yaml"); err != nil {
		t.Errorf("artifacts subtree is not rooted correctly: %v", err)
	}
	if _, err := fs.ReadFile(a, "artifacts/files/system/etc.yaml"); err == nil {
		t.Error("artifacts subtree is doubly nested")
	}
}

func TestVersionIsRecorded(t *testing.T) {
	release, commit := Version()
	if release == "unknown" || release == "" {
		t.Errorf("no UAC release recorded: %q", release)
	}
	if commit == "unknown" || commit == "" {
		t.Errorf("no UAC commit recorded: %q", commit)
	}
	t.Logf("embedded UAC %s (%s)", release, commit)
}

func TestReadFileReturnsACopy(t *testing.T) {
	f, err := FS()
	if err != nil {
		t.Fatal(err)
	}
	first, err := fs.ReadFile(f, "VERSION")
	if err != nil {
		t.Fatal(err)
	}
	for i := range first {
		first[i] = 'X'
	}
	second, err := fs.ReadFile(f, "VERSION")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(string(second), "XX") {
		t.Fatal("a caller mutated the embedded corpus; ReadFile must return a copy")
	}
}

func TestWalkIsSorted(t *testing.T) {
	f, err := FS()
	if err != nil {
		t.Fatal(err)
	}
	var prev string
	fs.WalkDir(f, "artifacts", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if prev != "" && p < prev {
			t.Errorf("walk out of order: %q came after %q", p, prev)
		}
		prev = p
		return nil
	})
}

func TestExtractWritesEverything(t *testing.T) {
	dir := t.TempDir()
	n := 0
	err := Extract(dir, func(name string, data []byte) error {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return err
		}
		n++
		return os.WriteFile(full, data, 0644)
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 400 {
		t.Errorf("extracted only %d files", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "artifacts/bodyfile/bodyfile.yaml")); err != nil {
		t.Errorf("extracted tree is missing a known artifact: %v", err)
	}
}

// TestEmbeddedMatchesCheckout is the staleness guard: after updating the UAC
// checkout, `go generate ./internal/uacdata` has to be re-run, and nothing else
// would notice if it were forgotten.
func TestEmbeddedMatchesCheckout(t *testing.T) {
	root := uacpath.Find()
	if root == "" {
		t.Skip("no UAC checkout to compare against; set UAC_ROOT")
	}
	embedded, err := FS()
	if err != nil {
		t.Fatal(err)
	}

	var missing, differing, extra int
	onDisk := map[string]bool{}
	for _, sub := range []string{"artifacts", "config", "profiles"} {
		filepath.WalkDir(filepath.Join(root, sub), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			onDisk[rel] = true

			want, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			got, err := fs.ReadFile(embedded, rel)
			if err != nil {
				missing++
				if missing <= 5 {
					t.Errorf("in the checkout but not embedded: %s", rel)
				}
				return nil
			}
			if string(got) != string(want) {
				differing++
				if differing <= 5 {
					t.Errorf("embedded copy differs from the checkout: %s", rel)
				}
			}
			return nil
		})
	}
	fs.WalkDir(embedded, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p == "VERSION" {
			return err
		}
		if !onDisk[p] {
			extra++
			if extra <= 5 {
				t.Errorf("embedded but no longer in the checkout: %s", p)
			}
		}
		return nil
	})
	if missing+differing+extra > 0 {
		t.Errorf("embedded corpus is stale (%d missing, %d differing, %d removed); "+
			"run: go generate ./internal/uacdata", missing, differing, extra)
	}
}

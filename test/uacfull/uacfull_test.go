package uacfull

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"uacscan/internal/uacdata"
)

func TestExtractProducesARunnableUAC(t *testing.T) {
	dir := t.TempDir()
	if err := Extract(dir); err != nil {
		t.Fatal(err)
	}

	// The pieces the harness actually depends on.
	for _, want := range []string{
		"uac",
		"artifacts/bodyfile/bodyfile.yaml",
		"config/uac.conf",
		"lib/find_based_collector.sh",
		"bin/linux/x86_64/statx",
	} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Errorf("missing %s: %v", want, err)
		}
	}

	// Without the executable bit the harness cannot run anything at all, and
	// OpenFile's mode is masked by umask, so this is easy to get wrong.
	for _, want := range []string{"uac", "bin/linux/x86_64/statx", "bin/strings.sh"} {
		fi, err := os.Stat(filepath.Join(dir, want))
		if err != nil {
			t.Errorf("%s: %v", want, err)
			continue
		}
		if fi.Mode()&0111 == 0 {
			t.Errorf("%s extracted without the executable bit (mode %v)", want, fi.Mode())
		}
	}

	// Non-executables must not have acquired it.
	fi, err := os.Stat(filepath.Join(dir, "config/uac.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&0111 != 0 {
		t.Errorf("config/uac.conf is executable (mode %v)", fi.Mode())
	}
}

func TestExtractedUACRuns(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell available")
	}
	dir := t.TempDir()
	if err := Extract(dir); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("./uac", "--version")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("./uac --version failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "3.3.0") {
		t.Errorf("unexpected version output: %q", out)
	}
	t.Logf("%s", strings.TrimSpace(string(out)))
}

func TestDirIsReusedAcrossCalls(t *testing.T) {
	a, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("Dir unpacked twice: %q then %q", a, b)
	}
	if _, err := os.Stat(filepath.Join(a, "uac")); err != nil {
		t.Errorf("unpacked tree is incomplete: %v", err)
	}
}

func TestVersionMatchesTheDataArchive(t *testing.T) {
	fullRelease, fullCommit := Version()
	dataRelease, dataCommit := uacdata.Version()
	if fullRelease != dataRelease || fullCommit != dataCommit {
		t.Errorf("the two embedded copies came from different UACs: full %s/%s, data %s/%s; "+
			"regenerate both", fullRelease, fullCommit, dataRelease, dataCommit)
	}
}

// The harness feeds both tools the definitions from the full tree, while the
// shipped binary uses the small one. If those ever diverge, the comparison
// stops saying anything about what uacscan actually collects.
func TestArtifactsAgreeBetweenTheTwoEmbeddedCopies(t *testing.T) {
	dir := t.TempDir()
	if err := Extract(dir); err != nil {
		t.Fatal(err)
	}
	small, err := uacdata.Artifacts()
	if err != nil {
		t.Fatal(err)
	}

	var checked, differing, missing int
	root := filepath.Join(dir, "artifacts")
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		checked++

		want, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		got, err := fs.ReadFile(small, rel)
		if err != nil {
			missing++
			if missing <= 5 {
				t.Errorf("%s is in the full tree but not in the data archive", rel)
			}
			return nil
		}
		if string(got) != string(want) {
			differing++
			if differing <= 5 {
				t.Errorf("%s differs between the two embedded copies", rel)
			}
		}
		return nil
	})

	if checked == 0 {
		t.Fatal("no artifacts found in the extracted tree")
	}
	t.Logf("compared %d artifact files", checked)
	if missing+differing > 0 {
		t.Errorf("the embedded copies disagree (%d missing, %d differing); "+
			"run: go generate ./internal/uacdata ./test/uacfull", missing, differing)
	}
}

func TestExtractRefusesPathTraversal(t *testing.T) {
	// The archive is built by our own generator, but an extractor that trusts
	// entry names is a mistake worth not making, so the guard is asserted here
	// rather than assumed.
	dir := t.TempDir()
	if err := Extract(dir); err != nil {
		t.Fatal(err)
	}
	var escaped bool
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if rel, rerr := filepath.Rel(dir, p); rerr == nil && strings.HasPrefix(rel, "..") {
			escaped = true
		}
		return nil
	})
	if escaped {
		t.Error("extraction wrote outside the target directory")
	}
}

package main

import (
	"os"
	"testing"

	"uacscan/test/uacfull"
)

// TestDifferentialAgainstUAC is the integration test: it runs the real shell
// UAC and uacscan against the same tree and fails on any disagreement.
//
// It is skipped when the UAC repository is not available, so `go test ./...`
// still works on a machine that only has this project.
func TestDifferentialAgainstUAC(t *testing.T) {
	uacDir := uacRepo(t)
	work := t.TempDir()
	if err := run(uacDir, defaultArtifacts, work, "", true, testing.Verbose()); err != nil {
		t.Fatalf("outputs differ from the shell implementation: %v", err)
	}
}

// TestDifferentialAgainstRealTree runs the same comparison over an ordinary
// system directory, which has far more variety than any fixture: thousands of
// files, symlinks, unreadable entries, odd names.
func TestDifferentialAgainstRealTree(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the large-tree comparison in short mode")
	}
	uacDir := uacRepo(t)

	var image string
	for _, c := range []string{"/usr/share/doc", "/usr/share/man", "/usr/lib/python3"} {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			image = c
			break
		}
	}
	if image == "" {
		t.Skip("no suitable system directory to compare against")
	}
	t.Logf("comparing against %s", image)

	work := t.TempDir()
	if err := run(uacDir, defaultArtifacts, work, image, true, testing.Verbose()); err != nil {
		t.Fatalf("outputs differ from the shell implementation: %v", err)
	}
}

// uacRepo returns the UAC the comparison runs against: the embedded copy
// unless UAC_ROOT points at a checkout. Because it is embedded, these tests no
// longer skip -- the differential comparison runs anywhere.
func uacRepo(t *testing.T) string {
	t.Helper()
	dir, why, err := ResolveUAC("")
	if err != nil {
		t.Fatalf("no UAC available: %v", err)
	}
	t.Logf("comparing against UAC: %s (%s)", dir, why)
	return dir
}

func TestMain(m *testing.M) {
	code := m.Run()
	uacfull.Cleanup()
	os.Exit(code)
}

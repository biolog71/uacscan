package outdir

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestName(t *testing.T) {
	now := time.Date(2026, 8, 8, 17, 4, 5, 0, time.UTC)
	if got, want := Name("evidence-01", "linux", now), "uacscan-evidence-01-linux-20260808170405"; got != want {
		t.Errorf("Name = %q, want %q", got, want)
	}
	// A missing hostname or OS must still produce a usable directory name.
	if got := Name("", "", now); got != "uacscan-unknown-unknown-20260808170405" {
		t.Errorf("Name with blanks = %q", got)
	}
	// The timestamp is UTC regardless of the examiner's timezone.
	local := time.Date(2026, 8, 8, 17, 4, 5, 0, time.FixedZone("X", 3*3600))
	if got := Name("h", "linux", local); !strings.HasSuffix(got, "20260808140405") {
		t.Errorf("Name did not normalise to UTC: %q", got)
	}
}

func TestNameSanitisesAwkwardHostnames(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, host := range []string{"a/b", "a b", "a:b", `a"b`, "a|b"} {
		got := Name(host, "linux", now)
		if strings.ContainsAny(got, `/\*?:"<>| `) {
			t.Errorf("Name(%q) = %q, still contains an unusable character", host, got)
		}
	}
}

func TestCreateMakesAFreshDirectory(t *testing.T) {
	dest := t.TempDir()
	got, err := Create(dest, "uacscan-host-linux-20260808170405")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(got)
	if err != nil || !fi.IsDir() {
		t.Fatalf("output directory not created: %v", err)
	}
	if filepath.Dir(got) != dest {
		t.Errorf("created %q, expected it inside %q", got, dest)
	}
}

// Two runs in the same second must not be handed the same directory.
func TestCreateNeverReturnsAnExistingDirectory(t *testing.T) {
	dest := t.TempDir()
	const base = "uacscan-host-linux-20260808170405"

	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		got, err := Create(dest, base)
		if err != nil {
			t.Fatal(err)
		}
		if seen[got] {
			t.Fatalf("Create returned %q twice", got)
		}
		seen[got] = true
	}
	if len(seen) != 5 {
		t.Errorf("got %d distinct directories, want 5", len(seen))
	}
}

// The property that makes concurrent collections safe: no two callers, however
// they race, can be given the same directory.
func TestCreateIsSafeUnderConcurrency(t *testing.T) {
	dest := t.TempDir()
	const base = "uacscan-host-linux-20260808170405"
	const n = 32

	var (
		mu    sync.Mutex
		paths = map[string]bool{}
		wg    sync.WaitGroup
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := Create(dest, base)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if paths[got] {
				t.Errorf("two concurrent callers were given %q", got)
			}
			paths[got] = true
		}()
	}
	wg.Wait()
	if len(paths) != n {
		t.Errorf("got %d distinct directories from %d callers", len(paths), n)
	}
}

func TestCreateRejectsAnEmptyDestination(t *testing.T) {
	if _, err := Create("", "base"); err == nil {
		t.Error("expected an error for an empty destination")
	}
	if _, err := Create(t.TempDir(), ""); err == nil {
		t.Error("expected an error for an empty base name")
	}
}

func TestHostnameComesFromTheImage(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etc/hostname"), []byte("evidence-01\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := Hostname(dir); got != "evidence-01" {
		t.Errorf("Hostname = %q, want the image's, not the workstation's", got)
	}
}

func TestHostnameFallbacks(t *testing.T) {
	cases := []struct {
		file, body, want string
	}{
		{"etc/rc.conf", "hostname=\"bsd-box\"\nsomething_else=1\n", "bsd-box"},
		{"etc/myname", "openbsd-box\n", "openbsd-box"},
		{"etc/nodename", "solaris-box\n", "solaris-box"},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		full := filepath.Join(dir, tc.file)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(tc.body), 0644); err != nil {
			t.Fatal(err)
		}
		if got := Hostname(dir); got != tc.want {
			t.Errorf("%s: Hostname = %q, want %q", tc.file, got, tc.want)
		}
	}

	// An image with nothing to go on must not silently report the examiner's
	// own host name.
	if got := Hostname(t.TempDir()); got != "unknown" {
		t.Errorf("Hostname of an unidentifiable image = %q, want unknown", got)
	}
}

func TestHostnameUsesTheRunningSystemOnlyWhenCollectingFromRoot(t *testing.T) {
	host, err := os.Hostname()
	if err != nil {
		t.Skip("no host name available")
	}
	if got := Hostname("/"); got != host {
		t.Errorf("live collection Hostname = %q, want %q", got, host)
	}
}

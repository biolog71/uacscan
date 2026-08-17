package fsref

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestModeStringMatchesGNUStat(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		mode os.FileMode
		want string
	}{
		{"plain", 0644, "-rw-r--r--"},
		{"exec", 0755, "-rwxr-xr-x"},
		{"none", 0000, "----------"},
		{"suid", 0755 | os.ModeSetuid, "-rwsr-xr-x"},
		{"suid_noexec", 0644 | os.ModeSetuid, "-rwSr--r--"},
		{"sgid", 0755 | os.ModeSetgid, "-rwxr-sr-x"},
		{"sgid_noexec", 0644 | os.ModeSetgid, "-rw-r-Sr--"},
		{"sticky_file", 0755 | os.ModeSticky, "-rwxr-xr-t"},
		{"world_write", 0666, "-rw-rw-rw-"},
	}
	for _, tc := range cases {
		p := filepath.Join(dir, tc.name)
		if err := os.WriteFile(p, nil, 0644); err != nil {
			t.Fatal(err)
		}
		// Chmod separately: WriteFile's perm is masked by umask.
		if err := os.Chmod(p, tc.mode); err != nil {
			t.Fatal(err)
		}
		f, err := Resolve(p, "/"+tc.name, 1)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := f.ModeString(); got != tc.want {
			t.Errorf("%s: ModeString() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestModeStringTypes(t *testing.T) {
	dir := t.TempDir()

	sub := filepath.Join(dir, "d")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	f, err := Resolve(sub, "/d", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.ModeString(); got != "drwxr-xr-x" {
		t.Errorf("dir ModeString() = %q", got)
	}
	if f.TypeChar() != 'd' || !f.IsDir() {
		t.Errorf("dir type = %q", f.TypeChar())
	}

	link := filepath.Join(dir, "l")
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	f, err = Resolve(link, "/l", 1)
	if err != nil {
		t.Fatal(err)
	}
	// Must not follow: a symlink to a nonexistent target still resolves.
	if !f.IsSymlink() {
		t.Errorf("symlink not detected, mode=%q", f.ModeString())
	}
	if got, _ := f.Link(); got != "target" {
		t.Errorf("Link() = %q, want %q", got, "target")
	}

	fifo := filepath.Join(dir, "p")
	if err := syscall.Mkfifo(fifo, 0644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	f, err = Resolve(fifo, "/p", 1)
	if err != nil {
		t.Fatal(err)
	}
	if f.TypeChar() != 'p' {
		t.Errorf("fifo type = %q", f.TypeChar())
	}
}

func TestResolveDoesNotFollowSymlinkToDir(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "realdir")
	if err := os.Mkdir(real, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	f, err := Resolve(link, "/link", 1)
	if err != nil {
		t.Fatal(err)
	}
	if f.IsDir() {
		t.Fatal("Resolve followed a symlink to a directory; walk would loop")
	}
}

func TestCacheAvoidsRestat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	ref, err := Resolve(p, "/f", 1)
	if err != nil {
		t.Fatal(err)
	}
	c := NewCache(dir)
	c.Set(ref)

	if !c.Hit(p) {
		t.Error("cache miss on the primed real path")
	}
	if !c.Hit("/f") {
		t.Error("cache miss on the primed relative path")
	}
	got, err := c.Get("/f")
	if err != nil {
		t.Fatal(err)
	}
	if got != ref {
		t.Error("Get returned a different record; it re-stat'ed")
	}
	if c.Hit("/other") {
		t.Error("unexpected hit for an unrelated path")
	}
}

func TestCacheGetOnMissStillWorks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "standalone"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	c := NewCache(dir)
	// Nothing primed: a collector called outside a walk must still be correct.
	got, err := c.Get("/standalone")
	if err != nil {
		t.Fatal(err)
	}
	if got.Size != 5 {
		t.Errorf("Size = %d, want 5", got.Size)
	}
	if got.Path != "/standalone" {
		t.Errorf("Path = %q, want /standalone", got.Path)
	}
}

func TestRelAndJoin(t *testing.T) {
	cases := []struct{ root, real, rel string }{
		{"/mnt/img", "/mnt/img/etc/passwd", "/etc/passwd"},
		{"/mnt/img/", "/mnt/img/etc/passwd", "/etc/passwd"},
		{"/mnt/img", "/mnt/img", "/"},
		{"/", "/etc/passwd", "/etc/passwd"},
		{"", "/etc/passwd", "/etc/passwd"},
	}
	for _, tc := range cases {
		if got := Rel(tc.real, tc.root); got != tc.rel {
			t.Errorf("Rel(%q, %q) = %q, want %q", tc.real, tc.root, got, tc.rel)
		}
	}
	if got := Join("/mnt/img", "/etc/passwd"); got != "/mnt/img/etc/passwd" {
		t.Errorf("Join = %q", got)
	}
	if got := Join("/", "/etc/passwd"); got != "/etc/passwd" {
		t.Errorf("Join(/) = %q", got)
	}
}

func TestStatxReportsBirthTimeWhereSupported(t *testing.T) {
	if sysStatx == 0 {
		t.Skip("no statx on this platform")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := Resolve(p, "/f", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !f.HasBtime {
		t.Skip("filesystem does not report birth time")
	}
	if f.Btime.IsZero() {
		t.Error("HasBtime set but Btime is zero")
	}
	// Whether or not the file is immutable, the filesystem should at least say
	// whether it knows -- that is what replaces the FS_IOC_GETFLAGS ioctl.
	if _, known := f.Immutable(); !known {
		t.Log("filesystem does not report the immutable attribute")
	}
}

// DevMatchesRealStat is the regression test for a real, previously-shipped
// bug: offDevMajor/offDevMinor pointed at stx_rdev (the device a block/char
// special file *represents*, zero for everything else) instead of stx_dev
// (the device *containing* the file). Every regular file and directory
// reported Dev=0, so the walker's cross-device check could never fire --
// -cross-device silently did nothing no matter what it was set to.
//
// This can only be caught against a tree that spans more than one real
// filesystem, which no synthetic fixture provides, so the test is best-effort:
// it looks for a second mount point among common locations and skips if none
// is found, rather than asserting anything false-positive on a single-device
// CI runner.
func TestDevMatchesRealStat(t *testing.T) {
	if sysStatx == 0 {
		t.Skip("no statx on this platform")
	}

	rootDev := statDev(t, "/")

	// Every file on the same device as / must report the same Dev,
	// regardless of which directory it lives in.
	f, err := Resolve("/", "/", 0)
	if err != nil {
		t.Fatal(err)
	}
	if f.Dev != rootDev {
		t.Errorf("Dev for / = %d, want %d (from stat -c %%d)", f.Dev, rootDev)
	}

	for _, candidate := range []string{"/boot", "/boot/efi", "/proc", "/sys", "/dev"} {
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		otherDev := statDev(t, candidate)
		if otherDev == rootDev {
			continue // same filesystem as /; not useful for this check
		}
		got, err := Resolve(candidate, candidate, 0)
		if err != nil {
			continue
		}
		if got.Dev == 0 {
			t.Errorf("%s: Dev decoded as 0; the stx_dev/stx_rdev offsets are swapped again", candidate)
		}
		if got.Dev != otherDev {
			t.Errorf("%s: Dev = %d, want %d (from stat -c %%d, differs from root's %d)",
				candidate, got.Dev, otherDev, rootDev)
		}
		if got.Dev == rootDev {
			t.Errorf("%s: Dev matches root (%d) despite being on a different real filesystem",
				candidate, rootDev)
		}
		return // found one genuine cross-device pair; that is enough to prove the fix
	}
	t.Skip("no second mount point found among common locations; cannot exercise the cross-device path")
}

// statDev shells out to the system's own stat(1) as an independent oracle,
// so this test does not just check the code against itself.
func statDev(t *testing.T, path string) uint64 {
	t.Helper()
	out, err := exec.Command("stat", "-c", "%d", path).Output()
	if err != nil {
		t.Skipf("system stat(1) unavailable: %v", err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		t.Fatalf("parsing stat output %q: %v", out, err)
	}
	return n
}

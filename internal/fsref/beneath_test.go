package fsref

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanImagePathAbsorbsTraversal(t *testing.T) {
	// "/" is the image root, so leading ".." cannot climb past it -- the value
	// resolves back inside the image rather than escaping to the host.
	cases := []struct{ in, want string }{
		{"/etc/passwd", "/etc/passwd"},
		{"/../../../../etc/shadow", "/etc/shadow"},
		{"/etc/../../../root/.ssh/id_rsa", "/root/.ssh/id_rsa"},
		{"/home/alice/../../../../etc/shadow", "/etc/shadow"},
		{"/a/./b//c", "/a/b/c"},
		{"/", "/"},
	}
	for _, tc := range cases {
		got, err := CleanImagePath(tc.in)
		if err != nil {
			t.Errorf("CleanImagePath(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("CleanImagePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.Contains(got, "..") {
			t.Errorf("CleanImagePath(%q) = %q, still contains ..", tc.in, got)
		}
	}
}

func TestCleanImagePathRejectsUnusableValues(t *testing.T) {
	for _, in := range []string{"relative/path", ".bash_history", "$HOME/x", "", "/x\x00y"} {
		if got, err := CleanImagePath(in); err == nil {
			t.Errorf("CleanImagePath(%q) accepted, returned %q", in, got)
		}
	}
}

// The attack cleaning cannot see: a symlinked directory component sends the
// resolution out of the image entirely.
func TestResolveBeneathRefusesSymlinkedComponents(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("host data"), 0644); err != nil {
		t.Fatal(err)
	}

	image := t.TempDir()
	if err := os.MkdirAll(filepath.Join(image, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(image, "etc/passwd"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	// A hostile image plants an absolute symlink pointing at the host.
	if err := os.Symlink(outside, filepath.Join(image, "escape")); err != nil {
		t.Fatal(err)
	}

	// An ordinary path inside the image still resolves.
	if _, err := ResolveBeneath(image, "/etc/passwd"); err != nil {
		t.Errorf("a legitimate path was refused: %v", err)
	}

	// Through the symlink it must not.
	if _, err := ResolveBeneath(image, "/escape/secret"); err == nil {
		t.Fatal("resolved through a symlink and read a file outside the image")
	} else if !errors.Is(err, ErrEscapesRoot) {
		t.Logf("refused with %v", err) // any refusal is acceptable
	}

	// And traversal in the path itself is absorbed, not followed.
	f, err := ResolveBeneath(image, "/../../../../etc/passwd")
	if err != nil {
		t.Fatalf("traversal should resolve back inside the image: %v", err)
	}
	if f.Path != "/etc/passwd" {
		t.Errorf("resolved to %q, want /etc/passwd", f.Path)
	}
	if !strings.HasPrefix(f.Real, image) {
		t.Errorf("real path %q left the image root %q", f.Real, image)
	}
}

func TestDestinationUnder(t *testing.T) {
	dir := "/out/[root]"
	cases := []struct {
		rel, want string
		ok        bool
	}{
		{"/etc/passwd", "/out/[root]/etc/passwd", true},
		{"/../../etc/shadow", "/out/[root]/etc/shadow", true}, // absorbed, stays inside
		{"etc/passwd", "/out/[root]/etc/passwd", true},
	}
	for _, tc := range cases {
		got, err := DestinationUnder(dir, tc.rel)
		if (err == nil) != tc.ok {
			t.Errorf("DestinationUnder(%q) err = %v", tc.rel, err)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("DestinationUnder(%q) = %q, want %q", tc.rel, got, tc.want)
		}
		if err == nil && !strings.HasPrefix(got, dir+"/") {
			t.Errorf("DestinationUnder(%q) = %q, escaped %q", tc.rel, got, dir)
		}
	}
}

// A symlink already sitting at the destination must not redirect the write.
func TestCreateNoFollowRefusesAnExistingSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "collected")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, err := CreateNoFollow(link, 0644); err == nil {
		t.Fatal("wrote through a symlink in the output tree")
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "original" {
		t.Errorf("the symlink target was modified: %q %v", b, err)
	}

	// A normal destination still works.
	f, err := CreateNoFollow(filepath.Join(dir, "fresh"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// Both containment mechanisms must reach the same verdict, so that a kernel
// without openat2 is demonstrably no less safe than one with it.
func TestBothContainmentMechanismsAgree(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("host"), 0644); err != nil {
		t.Fatal(err)
	}
	image := t.TempDir()
	for _, d := range []string{"etc", "var/log"} {
		if err := os.MkdirAll(filepath.Join(image, d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(image, "etc/passwd"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(image, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(image, "var/log/root")); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		path string
		ok   bool
	}{
		{"/etc/passwd", true},
		{"/escape/secret", false},
		{"/var/log/root/etc/passwd", false},
		{"/nonexistent/file", true}, // absent, not an escape
	}
	for _, tc := range cases {
		cleaned, err := CleanImagePath(tc.path)
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}

		kernelChecked, kernelErr := checkBeneathKernel(image, cleaned)
		portableErr := checkBeneath(image, cleaned)

		if kernelChecked && (kernelErr == nil) != (portableErr == nil) {
			t.Errorf("%s: openat2 says %v, the lstat check says %v",
				tc.path, kernelErr, portableErr)
		}
		allowed := portableErr == nil
		if kernelChecked {
			allowed = kernelErr == nil
		}
		if allowed != tc.ok {
			t.Errorf("%s: allowed=%v, want %v (kernel=%v portable=%v)",
				tc.path, allowed, tc.ok, kernelErr, portableErr)
		}
	}
}

// Confirms the kernel path is genuinely exercised here rather than silently
// falling back, which would make the test above vacuous.
func TestOpenat2IsExercisedWhereAvailable(t *testing.T) {
	image := t.TempDir()
	if err := os.MkdirAll(filepath.Join(image, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(image, "etc/passwd"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	checked, err := checkBeneathKernel(image, "/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if !checked {
		t.Skip("no openat2 on this kernel; the portable check is in use")
	}
	t.Log("openat2 is in use")
}

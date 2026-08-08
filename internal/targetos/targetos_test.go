package targetos

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestSupports(t *testing.T) {
	cases := []struct {
		supported []string
		target    OS
		want      bool
	}{
		{[]string{"all"}, Linux, true},
		{[]string{"all"}, MacOS, true},
		{[]string{"linux"}, Linux, true},
		{[]string{"linux"}, MacOS, false},
		{[]string{"linux", "macos"}, MacOS, true},
		{[]string{"freebsd", "netbsd", "openbsd"}, Linux, false},
		// No declaration means the artifact does not restrict itself.
		{nil, Linux, true},
		// Unknown target must not filter anything out; better to over-collect
		// than to silently drop artifacts because detection failed.
		{[]string{"linux"}, Unknown, true},
	}
	for _, tc := range cases {
		if got := Supports(tc.supported, tc.target); got != tc.want {
			t.Errorf("Supports(%v, %q) = %v, want %v", tc.supported, tc.target, got, tc.want)
		}
	}
}

func TestDetectFromMarkers(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  OS
	}{
		{"linux-os-release", []string{"etc/os-release", "etc/passwd"}, Linux},
		{"linux-debian", []string{"etc/debian_version"}, Linux},
		{"macos", []string{"System/Library/CoreServices/SystemVersion.plist"}, MacOS},
		{"macos-private-etc", []string{"private/etc/passwd"}, MacOS},
		{"freebsd", []string{"bin/freebsd-version"}, FreeBSD},
		{"solaris", []string{"etc/release"}, Solaris},
		{"aix", []string{"etc/objrepos"}, AIX},
		{"netbsd", []string{"netbsd"}, NetBSD},
		{"openbsd", []string{"bsd"}, OpenBSD},
		{"esxi", []string{"etc/vmware"}, ESXi},
		{"nothing", []string{"random/file"}, Unknown},
	}
	for _, tc := range cases {
		m := fstest.MapFS{}
		for _, f := range tc.files {
			m[f] = &fstest.MapFile{Data: []byte("x")}
		}
		got, _ := DetectFS(m)
		if got != tc.want {
			t.Errorf("%s: DetectFS = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A NetScaler image is also a FreeBSD image, and an ESXi image looks Linux-ish.
// The more specific marker has to win or the wrong artifact set gets collected.
func TestDetectPrefersTheMoreSpecificSystem(t *testing.T) {
	netscaler := fstest.MapFS{
		"flash/nsconfig":      &fstest.MapFile{Data: []byte("x")},
		"bin/freebsd-version": &fstest.MapFile{Data: []byte("x")},
		"etc/fstab":           &fstest.MapFile{Data: []byte("x")},
	}
	if got, _ := DetectFS(netscaler); got != NetScaler {
		t.Errorf("NetScaler image detected as %q", got)
	}

	esxi := fstest.MapFS{
		"etc/vmware": &fstest.MapFile{Data: []byte("x")},
		"etc/fstab":  &fstest.MapFile{Data: []byte("x")},
	}
	if got, _ := DetectFS(esxi); got != ESXi {
		t.Errorf("ESXi image detected as %q", got)
	}

	// macOS carries /private/etc but also has an /etc symlink; it must not be
	// mistaken for Linux.
	mac := fstest.MapFS{
		"private/etc/passwd": &fstest.MapFile{Data: []byte("x")},
		"etc/fstab":          &fstest.MapFile{Data: []byte("x")},
	}
	if got, _ := DetectFS(mac); got != MacOS {
		t.Errorf("macOS image detected as %q", got)
	}
}

func TestDetectOnRealDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etc/os-release"), []byte("ID=debian\n"), 0644); err != nil {
		t.Fatal(err)
	}
	got, evidence := Detect(dir)
	if got != Linux {
		t.Errorf("Detect = %q, want linux", got)
	}
	if evidence != "etc/os-release" {
		t.Errorf("evidence = %q", evidence)
	}
}

func TestResolve(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "etc"), 0755)
	os.WriteFile(filepath.Join(dir, "etc/os-release"), []byte("ID=x\n"), 0644)

	// Override wins over everything.
	got, why, err := Resolve("macos", dir)
	if err != nil || got != MacOS {
		t.Errorf("override: got %q (%v)", got, err)
	}
	if why == "" {
		t.Error("Resolve must explain its choice")
	}

	// Detection from the image.
	got, why, err = Resolve("", dir)
	if err != nil || got != Linux {
		t.Errorf("detect: got %q (%v)", got, err)
	}
	if want := "detected from"; len(why) < len(want) || why[:len(want)] != want {
		t.Errorf("reason = %q, expected it to cite the marker", why)
	}

	// Mount point / means the host is the image.
	got, _, err = Resolve("", "/")
	if err != nil || got != Host() {
		t.Errorf("live: got %q, want %q (%v)", got, Host(), err)
	}

	// An unidentifiable offline image must NOT be assumed to be the examiner's
	// operating system. Doing so would filter out every macos artifact from a
	// partial macOS image examined on Linux, and the collection would look
	// complete. Unknown disables the filter instead.
	empty := t.TempDir()
	got, why, err = Resolve("", empty)
	if err != nil {
		t.Fatal(err)
	}
	if got != Unknown {
		t.Errorf("unidentified image resolved to %q; it must be Unknown so that "+
			"no artifact is filtered out on a guess", got)
	}
	if why == "" {
		t.Error("the outcome must be explained")
	}
	// And Unknown really must disable filtering.
	if !Supports([]string{"macos"}, got) {
		t.Error("a macos artifact was filtered out for an unidentified image")
	}

	// A bad override is an error, not a silent default.
	if _, _, err := Resolve("windows", dir); err == nil {
		t.Error("expected an error for an unsupported operating system")
	}
}

func TestValidCoversEveryNameTheCorpusUses(t *testing.T) {
	// These are the values that actually appear in supported_os across UAC's
	// artifacts; every one must be accepted by -s.
	for _, name := range []string{
		"aix", "esxi", "freebsd", "linux", "macos",
		"netbsd", "netscaler", "openbsd", "solaris",
	} {
		if !Valid(name) {
			t.Errorf("%q is used by the corpus but rejected", name)
		}
	}
	if Valid("all") {
		t.Error(`"all" is a wildcard in supported_os, not a selectable target`)
	}
}

package fileattr

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildCapAttr assembles a security.capability value the way the kernel stores
// one, so the decoder can be tested without needing a privileged file.
func buildCapAttr(rev uint32, effective bool, permitted, inheritable uint64) []byte {
	magic := rev
	if effective {
		magic |= vfsCapFlagsEffective
	}
	words := 2
	if rev == vfsCapRevision1 {
		words = 1
	}
	buf := make([]byte, 4+8*words)
	binary.LittleEndian.PutUint32(buf[0:4], magic)
	for i := 0; i < words; i++ {
		binary.LittleEndian.PutUint32(buf[4+i*8:], uint32(permitted>>(32*i)))
		binary.LittleEndian.PutUint32(buf[8+i*8:], uint32(inheritable>>(32*i)))
	}
	return buf
}

func TestCapabilitiesMatchesGetcapOutput(t *testing.T) {
	const capNetRaw = 13
	const capNetAdmin = 12
	const capChown = 0

	cases := []struct {
		name string
		attr []byte
		want string
	}{
		{
			// What /usr/bin/ping actually carries.
			"ping",
			buildCapAttr(vfsCapRevision2, true, 1<<capNetRaw, 0),
			"cap_net_raw=ep",
		},
		{
			"two caps share a flag set",
			buildCapAttr(vfsCapRevision2, true, 1<<capNetAdmin|1<<capNetRaw, 0),
			"cap_net_admin,cap_net_raw=ep",
		},
		{
			"permitted only, effective bit clear",
			buildCapAttr(vfsCapRevision2, false, 1<<capChown, 0),
			"cap_chown=p",
		},
		{
			"inheritable as well",
			buildCapAttr(vfsCapRevision2, true, 1<<capChown, 1<<capChown),
			"cap_chown=eip",
		},
		{
			"revision 3 decodes like revision 2",
			append(buildCapAttr(vfsCapRevision3, true, 1<<capNetRaw, 0), 0, 0, 0, 0),
			"cap_net_raw=ep",
		},
		{
			"revision 1 has a single word",
			buildCapAttr(vfsCapRevision1, true, 1<<capNetRaw, 0),
			"cap_net_raw=ep",
		},
	}
	for _, tc := range cases {
		got, err := Capabilities(tc.attr)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: Capabilities = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestCapabilitiesRejectsRubbish(t *testing.T) {
	for _, attr := range [][]byte{
		nil,
		{1, 2, 3},
		buildCapAttr(0xFF000000, true, 1, 0), // unknown revision
		buildCapAttr(vfsCapRevision2, true, 0, 0), // no capabilities set
	} {
		if got, err := Capabilities(attr); err == nil {
			t.Errorf("accepted invalid attribute, returned %q", got)
		}
	}
}

func TestCapabilityNames(t *testing.T) {
	if got := CapabilityName(13); got != "cap_net_raw" {
		t.Errorf("13 = %q", got)
	}
	if got := CapabilityName(21); got != "cap_sys_admin" {
		t.Errorf("21 = %q", got)
	}
	// A capability newer than the table must still render, not panic.
	if got := CapabilityName(62); got != "cap_62" {
		t.Errorf("unknown = %q", got)
	}
}

// The flag layout was derived by measurement; this pins it.
func TestFlagStringLayout(t *testing.T) {
	if n := len(FlagString(0)); n != 22 {
		t.Errorf("flag string is %d wide, lsattr 1.47 prints 22", n)
	}
	if got := FlagString(0); got != strings.Repeat("-", 22) {
		t.Errorf("no flags = %q", got)
	}
	// Positions confirmed against the real lsattr.
	cases := []struct {
		flags uint32
		index int
		char  byte
	}{
		{FlagNoDump, 6, 'd'},
		{FlagNoAtime, 7, 'A'},
		{FlagExtents, 14, 'e'},
		{FlagImmutable, 4, 'i'},
		{FlagAppend, 5, 'a'},
	}
	for _, tc := range cases {
		s := FlagString(tc.flags)
		if s[tc.index] != tc.char {
			t.Errorf("flag %#x put %q at %d, want %q at %d (%q)",
				tc.flags, s[tc.index], tc.index, tc.char, tc.index, s)
		}
	}
	if got := FlagString(FlagNoDump | FlagNoAtime | FlagExtents); got != "------dA------e-------" {
		t.Errorf("combined = %q", got)
	}
}

func TestIsImmutable(t *testing.T) {
	if !IsImmutable(FlagImmutable | FlagExtents) {
		t.Error("immutable not detected")
	}
	if IsImmutable(FlagExtents) {
		t.Error("false positive")
	}
}

// The decisive test: render what the real lsattr renders, for real files.
func TestFlagStringAgreesWithSystemLsattr(t *testing.T) {
	lsattr, err := exec.LookPath("lsattr")
	if err != nil {
		t.Skip("lsattr not installed")
	}
	dir := t.TempDir()

	// Vary the flags a non-root user is allowed to set, so the comparison
	// covers more than the default state.
	files := map[string][]string{
		"plain":   nil,
		"nodump":  {"+d"},
		"noatime": {"+A"},
		"both":    {"+dA"},
	}
	var compared int
	for name, args := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if len(args) > 0 {
			if err := exec.Command("chattr", append(args, p)...).Run(); err != nil {
				continue // filesystem or permissions do not allow it
			}
		}
		out, err := exec.Command(lsattr, "-d", p).Output()
		if err != nil {
			continue
		}
		want := strings.Fields(string(out))
		if len(want) == 0 {
			continue
		}
		flags, err := GetFlags(p)
		if err != nil {
			t.Errorf("%s: GetFlags: %v", name, err)
			continue
		}
		if got := FlagString(flags); got != want[0] {
			t.Errorf("%s: rendered %q, lsattr printed %q", name, got, want[0])
		}
		compared++
	}
	if compared == 0 {
		t.Skip("could not compare against lsattr on this filesystem")
	}
	t.Logf("matched the system lsattr on %d files", compared)
}

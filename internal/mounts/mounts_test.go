package mounts

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeTable(t *testing.T, body string) Table {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mounts")
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return parseProcMounts(p)
}

func TestParse(t *testing.T) {
	tbl := writeTable(t, `sysfs /sys sysfs rw,nosuid,nodev,noexec 0 0
proc /proc proc rw,nosuid,nodev,noexec 0 0
/dev/sda1 / ext4 rw,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev 0 0
srv:/export /mnt/nfs nfs4 rw 0 0
`)
	if len(tbl) != 5 {
		t.Fatalf("parsed %d entries, want 5", len(tbl))
	}
	if tbl[2].Point != "/" || tbl[2].FSType != "ext4" {
		t.Errorf("root entry = %+v", tbl[2])
	}
}

func TestParseUnescapesMountPoints(t *testing.T) {
	// The kernel octal-escapes spaces in mount points.
	tbl := writeTable(t, "/dev/sdb1 /mnt/my\\040disk ext4 rw 0 0\n")
	if len(tbl) != 1 || tbl[0].Point != "/mnt/my disk" {
		t.Errorf("Point = %q, want %q", tbl[0].Point, "/mnt/my disk")
	}
}

func TestPointsForTypes(t *testing.T) {
	tbl := writeTable(t, `proc /proc proc rw 0 0
sysfs /sys sysfs rw 0 0
/dev/sda1 / ext4 rw 0 0
srv:/e /mnt/nfs nfs4 rw 0 0
srv:/e /mnt/nfs/deeper nfs4 rw 0 0
`)
	got := tbl.PointsForTypes([]string{"proc", "procfs"})
	if !reflect.DeepEqual(got, []string{"/proc"}) {
		t.Errorf("proc = %#v", got)
	}
	// Deepest first, so a nested mount is pruned before its parent.
	got = tbl.PointsForTypes([]string{"nfs4"})
	if !reflect.DeepEqual(got, []string{"/mnt/nfs/deeper", "/mnt/nfs"}) {
		t.Errorf("nfs = %#v, want deepest first", got)
	}
	if got := tbl.PointsForTypes(nil); got != nil {
		t.Errorf("no types should select nothing, got %#v", got)
	}
	if got := tbl.PointsForTypes([]string{"ntfs"}); got != nil {
		t.Errorf("unmatched type selected %#v", got)
	}
}

func TestPointsForTypesIsCaseInsensitive(t *testing.T) {
	tbl := writeTable(t, "none /sys SysFS rw 0 0\n")
	if got := tbl.PointsForTypes([]string{"sysfs"}); !reflect.DeepEqual(got, []string{"/sys"}) {
		t.Errorf("got %#v", got)
	}
}

// Offline, the mounts that matter are the ones inside the image, and their
// paths have to be image-relative to line up with everything else.
func TestUnderNarrowsAndRebasesToTheImage(t *testing.T) {
	tbl := writeTable(t, `proc /proc proc rw 0 0
/dev/sdb1 /mnt/image ext4 ro 0 0
/dev/sdb2 /mnt/image/boot ext2 ro 0 0
none /mnt/image/proc proc rw 0 0
/dev/sda1 / ext4 rw 0 0
`)
	got := tbl.Under("/mnt/image")
	want := Table{
		{Point: "/", FSType: "ext4", Source: "/dev/sdb1"},
		{Point: "/boot", FSType: "ext2", Source: "/dev/sdb2"},
		{Point: "/proc", FSType: "proc", Source: "none"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Under =\n %#v\nwant\n %#v", got, want)
	}
	// The examiner's own /proc must not appear: it is not part of the image.
	for _, m := range got {
		if m.Point == "/proc" && m.Source != "none" {
			t.Error("the host's /proc leaked into an offline collection")
		}
	}
	if n := len(tbl.Under("/")); n != len(tbl) {
		t.Errorf("Under(/) dropped entries: %d of %d", n, len(tbl))
	}
}

func TestLoadOnThisSystem(t *testing.T) {
	tbl := Load()
	if len(tbl) == 0 {
		t.Skip("no mount table on this platform")
	}
	var root bool
	for _, m := range tbl {
		if m.Point == "/" {
			root = true
		}
	}
	if !root {
		t.Error("the real mount table has no root entry")
	}
	t.Logf("%d mounts; proc/sysfs at %v", len(tbl), tbl.PointsForTypes([]string{"proc", "sysfs"}))
}

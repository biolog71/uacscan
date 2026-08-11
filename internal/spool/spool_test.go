package spool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A filename is attacker-controlled data on a hostile image, and Linux allows
// every byte in one except '/' and NUL -- including a newline. Written raw into
// a line-oriented output, such a name ends the record early and starts a new
// one, letting a suspect fabricate evidence by naming a file.
//
// The forged line here is a complete, valid mactime record. Before this was
// fixed it appeared in the bodyfile as its own parseable entry, describing a
// file that never existed.
func TestALineCannotBeForgedByANewlineInAPath(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w, err := s.Open("bodyfile/bodyfile#0", "bodyfile", "/bodyfile", "bodyfile.txt")
	if err != nil {
		t.Fatal(err)
	}
	forged := "0|/etc/cron.d/backdoor|99|-rwxrwxrwx|0|0|0|0|0|0|0"
	if err := w.WriteLine("0|/etc/evil\n" + forged + "|1|-rw-r--r--|0|0|1|0|0|0|0"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	m := s.Manifest()
	if len(m) != 1 {
		t.Fatalf("manifest has %d entries, want 1", len(m))
	}
	// One WriteLine call must produce exactly one line, whatever it contains.
	if m[0].Lines != 1 {
		t.Errorf("Lines = %d, want 1", m[0].Lines)
	}

	var got []string
	for line, err := range Lines(m[0].Path) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, line)
	}
	if len(got) != 1 {
		t.Fatalf("read back %d lines, want 1: %q", len(got), got)
	}
	if strings.HasPrefix(got[0], forged) {
		t.Error("the forged record became a line of its own")
	}
	if strings.ContainsAny(got[0], "\n\r") {
		t.Error("a raw newline survived into the output")
	}
	// The evidence must still be there, just neutralised, so an examiner can
	// see the real name -- a file named this way is itself worth noticing.
	if !strings.Contains(got[0], `\n`) {
		t.Errorf("the newline was dropped rather than escaped: %q", got[0])
	}
}

// The escaping must not disturb ordinary paths: the output is byte-compared
// against UAC's, so a gratuitous difference would be a real regression.
func TestOrdinaryPathsAreWrittenUnchanged(t *testing.T) {
	for _, path := range []string{
		"0|/etc/passwd|1|-rw-r--r--|0|0|100|1|2|3|0",
		`0|/home/user/Backup (2024)/file [1].txt|2|-rw-r--r--|0|0|1|1|2|3|0`,
		"0|/tmp/naïve-ファイル|3|-rw-r--r--|0|0|1|1|2|3|0",
		`0|/tmp/back\slash|4|-rw-r--r--|0|0|1|1|2|3|0`,
	} {
		if got := escapeControl(path); got != path {
			t.Errorf("escapeControl(%q) = %q, want it unchanged", path, got)
		}
	}
}

func TestControlBytesAreEscaped(t *testing.T) {
	cases := map[string]string{
		"a\nb":   `a\nb`,
		"a\rb":   `a\rb`,
		"a\x00b": `a\x00b`,
		"a\tb":   `a\tb`,
		"a\x1bb": `a\x1bb`, // an escape sequence must not reach a terminal raw
	}
	for in, want := range cases {
		if got := escapeControl(in); got != want {
			t.Errorf("escapeControl(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteAndStreamBack(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w, err := s.Open("bodyfile/bodyfile#0", "bodyfile", "/bodyfile", "bodyfile.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"0|/etc/passwd|1|-rw-r--r--|0|0|100|1|2|3|0", "0|/etc/shadow|2|-rw-------|0|0|50|1|2|3|0"}
	for _, l := range want {
		if err := w.WriteLine(l); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	m := s.Manifest()
	if len(m) != 1 {
		t.Fatalf("manifest has %d entries, want 1", len(m))
	}
	if m[0].Lines != 2 {
		t.Errorf("Lines = %d, want 2", m[0].Lines)
	}
	if m[0].Rel != "bodyfile/bodyfile.txt" {
		t.Errorf("Rel = %q", m[0].Rel)
	}

	var got []string
	for line, err := range Lines(m[0].Path) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, line)
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("streamed back %#v, want %#v", got, want)
	}
}

func TestSharedOutputFileAppends(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Open("rule#1", "paths", "/system", "shared.txt")
	b, _ := s.Open("rule#2", "paths", "/system", "shared.txt")
	if a != b {
		t.Fatal("two rules writing the same output_file got different writers")
	}
	a.WriteLine("one")
	b.WriteLine("two")
	s.Close()
	if a.Lines() != 2 {
		t.Errorf("Lines = %d, want 2", a.Lines())
	}
}

func TestEmptyOutputsAreRemoved(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open("r", "paths", "/system", "never_written.txt"); err != nil {
		t.Fatal(err)
	}
	w, _ := s.Open("r", "paths", "/system", "written.txt")
	w.WriteLine("x")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "system/never_written.txt")); !os.IsNotExist(err) {
		t.Error("empty spool file was not removed; UAC removes these")
	}
	if _, err := os.Stat(filepath.Join(root, "system/written.txt")); err != nil {
		t.Error("non-empty spool file was removed")
	}
	if len(s.Manifest()) != 1 {
		t.Errorf("manifest should list only the non-empty file, got %d", len(s.Manifest()))
	}
}

func TestSanitizeName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"bodyfile.txt", "bodyfile.txt"},
		{"a/b", "a_b"},
		{"a:b*c?d", "a_b_c_d"},
		{`a"b<c>d`, "a_b_c_d"},
		{"/leading", "leading"},
		{"a//b", "a_b"},
		{"", "_"},
	}
	for _, tc := range cases {
		if got := SanitizeName(tc.in); got != tc.want {
			t.Errorf("SanitizeName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Within one run, many lines accumulate and survive the flush boundary.
func TestLargeOutputSurvivesFlushing(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	w, err := s.Open("r", "paths", "/d", "f.txt")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5000; i++ {
		if err := w.WriteLine("a line long enough to cross the 64 KiB buffer several times over"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	n := 0
	for line, err := range Lines(filepath.Join(root, "d/f.txt")) {
		if err != nil {
			t.Fatal(err)
		}
		if line == "" {
			t.Fatal("a line was truncated at a flush boundary")
		}
		n++
	}
	if n != 5000 {
		t.Errorf("got %d lines, want 5000", n)
	}
}

// A second run must not append to the first. Reopening the same root is
// refused outright, which is what keeps two acquisitions from being mixed.
func TestReopeningACollectionIsRefused(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := s.Open("r", "paths", "/d", "f.txt")
	w.WriteLine("first run")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := NewStore(root); err == nil {
		t.Fatal("a second collection was allowed to append to the first")
	}

	n := 0
	for range Lines(filepath.Join(root, "d/f.txt")) {
		n++
	}
	if n != 1 {
		t.Errorf("the first run's output changed: %d lines", n)
	}
}

// Appending a second acquisition to an existing one produces line-oriented
// outputs holding both while copied files are selectively overwritten -- a
// mixture that looks like one coherent collection and is not.
func TestNewStoreRefusesANonEmptyDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "leftover.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(root); err == nil {
		t.Fatal("accepted a directory that already contains a collection")
	}

	// Absent and empty are both fine.
	if _, err := NewStore(filepath.Join(t.TempDir(), "fresh")); err != nil {
		t.Errorf("rejected a new directory: %v", err)
	}
	if _, err := NewStore(t.TempDir()); err != nil {
		t.Errorf("rejected an empty directory: %v", err)
	}
}

// A symlink where an output file should go must not redirect results out of the
// collection directory.
func TestOpenRefusesASymlinkedOutputFile(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "elsewhere.txt")
	if err := os.WriteFile(outside, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "system/suid.txt")); err != nil {
		t.Fatal(err)
	}

	s := &Store{Root: root, writers: map[string]*Writer{}, kinds: map[string]string{}, owners: map[string]string{}}
	if _, err := s.Open("r", "paths", "/system", "suid.txt"); err == nil {
		t.Fatal("opened through a symlink in the output tree")
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != "original" {
		t.Errorf("the symlink target was written: %q %v", b, err)
	}
}

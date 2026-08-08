package spool

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestContentSurvivesReopen(t *testing.T) {
	root := t.TempDir()
	s, _ := NewStore(root)
	w, _ := s.Open("r", "paths", "/d", "f.txt")
	for i := 0; i < 1000; i++ {
		w.WriteLine("line")
	}
	s.Close()

	// Reopening the same store must append, not truncate.
	s2, _ := NewStore(root)
	w2, _ := s2.Open("r", "paths", "/d", "f.txt")
	w2.WriteLine("appended")
	s2.Close()

	n := 0
	for range Lines(filepath.Join(root, "d/f.txt")) {
		n++
	}
	if n != 1001 {
		t.Errorf("got %d lines, want 1001", n)
	}
}

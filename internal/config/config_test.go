package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"uacscan/internal/uacdata"
)

// The defaults must match UAC's shipped config, because that is what the
// comparison runs against.
func TestDefaultsMatchShippedUACConfig(t *testing.T) {
	c := Default()
	if !reflect.DeepEqual(c.HashAlgorithm, []string{"md5", "sha1"}) {
		t.Errorf("HashAlgorithm = %v, want [md5 sha1]", c.HashAlgorithm)
	}
	if c.EnableFindAtime {
		t.Error("EnableFindAtime should default to false")
	}
	if !c.EnableFindMtime || !c.EnableFindCtime {
		t.Error("mtime and ctime should default to enabled")
	}
}

func TestLoadRealUACConfig(t *testing.T) {
	f, err := uacdata.FS()
	if err != nil {
		t.Fatal(err)
	}
	c, err := LoadFS(f, "config/uac.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.HashAlgorithm, []string{"md5", "sha1"}) {
		t.Errorf("HashAlgorithm = %v", c.HashAlgorithm)
	}
	if c.EnableFindAtime {
		t.Error("UAC ships enable_find_atime: false")
	}
	if len(c.ExcludeFileSystem) == 0 {
		t.Error("ExcludeFileSystem should be populated")
	}
	if len(c.ExcludePathPattern) != 0 {
		t.Errorf("ExcludePathPattern = %v, want empty", c.ExcludePathPattern)
	}
}

func TestMissingFileYieldsDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "absent.conf"))
	if err != nil {
		t.Fatalf("a missing config should not be an error: %v", err)
	}
	if !reflect.DeepEqual(c.HashAlgorithm, []string{"md5", "sha1"}) {
		t.Errorf("HashAlgorithm = %v", c.HashAlgorithm)
	}
}

func TestOverrides(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "uac.conf")
	os.WriteFile(p, []byte("# comment\nhash_algorithm: [sha256]\nenable_find_atime: true\nmax_depth: 5\n"), 0644)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.HashAlgorithm, []string{"sha256"}) {
		t.Errorf("HashAlgorithm = %v", c.HashAlgorithm)
	}
	if !c.EnableFindAtime {
		t.Error("enable_find_atime override ignored")
	}
	if c.MaxDepth != 5 {
		t.Errorf("MaxDepth = %d", c.MaxDepth)
	}
}

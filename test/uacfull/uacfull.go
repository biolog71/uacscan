// Package uacfull carries a complete UAC tree for the differential harness.
//
// This is separate from internal/uacdata on purpose. That package holds only
// the artifact definitions -- 49 KiB -- and is linked into the shipped binary.
// This one holds the whole shell implementation including bin/, which is 8.6 MB
// of precompiled tools for a dozen architectures. Nothing outside the harness
// imports it, so none of that reaches the uacscan executable.
//
// Unlike uacdata this really does unpack onto disk, because the harness has to
// execute ./uac: you cannot exec a script out of an in-memory filesystem.
//
// Regenerate after updating the UAC checkout:
//
//	go generate ./test/uacfull
package uacfull

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:generate go run ../../internal/uacdata/gen -uac ../../../uac -out uac-full.tar.gz -mode full

//go:embed uac-full.tar.gz
var archive []byte

var (
	once    sync.Once
	dir     string
	dirErr  error
	version string
	commit  string
)

// Dir unpacks the embedded UAC tree the first time it is called and returns the
// directory. Subsequent calls reuse it, so a test binary pays the unpacking
// cost once rather than per test.
//
// The directory is created under the OS temp dir and left in place: it is
// cheaper to let one 20 MB tree persist for the run than to unpack it
// repeatedly. Callers that care can pass it to Cleanup.
func Dir() (string, error) {
	once.Do(func() {
		d, err := os.MkdirTemp("", "uacfull-*")
		if err != nil {
			dirErr = err
			return
		}
		if err := Extract(d); err != nil {
			os.RemoveAll(d)
			dirErr = err
			return
		}
		dir = d
	})
	return dir, dirErr
}

// Cleanup removes a directory produced by Dir.
func Cleanup() {
	if dir != "" {
		os.RemoveAll(dir)
		dir = ""
	}
}

// Version reports which UAC release and commit the embedded tree came from.
func Version() (release, commitHash string) {
	if _, err := Dir(); err != nil {
		return "unknown", "unknown"
	}
	return version, commit
}

// Extract unpacks the embedded tree into dir.
func Extract(dir string) error {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return fmt.Errorf("uacfull: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("uacfull: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Refuse anything that would land outside dir. The archive is built by
		// our own generator, but an extractor that trusts path names is a
		// mistake worth not making.
		clean := filepath.Clean(filepath.FromSlash(hdr.Name))
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			return fmt.Errorf("uacfull: refusing entry outside the target directory: %q", hdr.Name)
		}
		target := filepath.Join(dir, clean)

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		mode := os.FileMode(hdr.Mode).Perm()
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		// OpenFile's mode is masked by umask, so the executable bit has to be
		// set explicitly -- without it the harness cannot run ./uac at all.
		if err := os.Chmod(target, mode); err != nil {
			return err
		}
		if clean == "VERSION" {
			version, commit = parseVersion(target)
		}
	}
	return nil
}

func parseVersion(path string) (release, commitHash string) {
	release, commitHash = "unknown", "unknown"
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "uac_version":
			release = v
		case "uac_commit":
			commitHash = v
		}
	}
	return release, commitHash
}

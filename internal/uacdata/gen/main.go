// Command gen builds the embedded UAC data archive.
//
// It packs the artifact definitions, uac.conf and the profiles from a UAC
// checkout into a single deterministic tar.gz that uacscan embeds, so the
// binary carries its own rule corpus and needs no path to a UAC tree at
// runtime.
//
// Run it with:
//
//	go generate ./internal/uacdata
//
// The archive is deterministic -- entries sorted, timestamps and ownership
// zeroed -- so rebuilding from the same UAC checkout produces an identical
// blob, and therefore an identical binary.
package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Only these subtrees are packed. The rest of the UAC repository is shell
// implementation that uacscan does not read.
var wanted = []string{"artifacts", "config", "profiles"}

func main() {
	var (
		uacDir = flag.String("uac", "", "path to the UAC repository (required)")
		out    = flag.String("out", "internal/uacdata/uac.tar.gz", "archive to write")
	)
	flag.Parse()

	if *uacDir == "" {
		fmt.Fprintln(os.Stderr, "gen: -uac is required")
		os.Exit(2)
	}
	if err := build(*uacDir, *out); err != nil {
		fmt.Fprintf(os.Stderr, "gen: %v\n", err)
		os.Exit(1)
	}
}

func build(uacDir, out string) error {
	version, commit := provenance(uacDir)

	type entry struct {
		name string
		data []byte
	}
	var entries []entry

	// A VERSION file rides along so a collection can always be traced back to
	// the artifact definitions that produced it. For a forensic tool that
	// provenance is not optional.
	entries = append(entries, entry{
		name: "VERSION",
		data: []byte(fmt.Sprintf("uac_version=%s\nuac_commit=%s\n", version, commit)),
	})

	for _, sub := range wanted {
		root := filepath.Join(uacDir, sub)
		if _, err := os.Stat(root); err != nil {
			return fmt.Errorf("%s: %w", root, err)
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if !d.Type().IsRegular() {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(uacDir, p)
			if err != nil {
				return err
			}
			entries = append(entries, entry{name: filepath.ToSlash(rel), data: data})
			return nil
		})
		if err != nil {
			return err
		}
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		return err
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	zw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(zw)

	var total int64
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0644,
			Size:     int64(len(e.data)),
			Typeflag: tar.TypeReg,
			ModTime:  time.Unix(0, 0).UTC(),
			Format:   tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(e.data); err != nil {
			return err
		}
		total += int64(len(e.data))
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	fmt.Printf("packed %d files (%.1f KiB) from UAC %s (%s) into %s (%.1f KiB)\n",
		len(entries), float64(total)/1024, version, commit, out, float64(fi.Size())/1024)
	return nil
}

// provenance reads the UAC version out of the main script and the commit from
// git, so the archive records exactly which corpus it came from.
func provenance(uacDir string) (version, commit string) {
	version, commit = "unknown", "unknown"

	if b, err := os.ReadFile(filepath.Join(uacDir, "uac")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "__UAC_VERSION="); ok {
				version = strings.Trim(v, `"'`)
				break
			}
		}
	}
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	cmd.Dir = uacDir
	if b, err := cmd.Output(); err == nil {
		commit = strings.TrimSpace(string(b))
	}
	return version, commit
}

// Command gen builds the embedded UAC archives.
//
// There are two, and one is derived from the other:
//
//	-mode full -uac DIR    packs a whole UAC checkout, for the differential
//	                       harness, which has to exec ./uac
//	-mode data -from FULL  extracts just the artifact definitions, uac.conf
//	                       and the profiles out of that full archive, for the
//	                       shipped binary
//
// The data archive is deliberately built from the full archive rather than
// from the checkout a second time. Two independent packs of the same tree can
// drift -- regenerate one, forget the other, and the harness quietly starts
// comparing against different definitions than the binary ships. Deriving one
// from the other makes that impossible rather than merely detectable.
//
// Run both, in this order:
//
//	go generate ./test/uacfull ./internal/uacdata
//
// Both archives are deterministic -- entries sorted, timestamps and ownership
// zeroed -- so the same checkout always produces identical blobs, and
// therefore a reproducible binary.
package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// dataSubtrees are the only parts uacscan itself reads. The rest of the UAC
// repository is shell implementation it replaced.
var dataSubtrees = []string{"artifacts", "config", "profiles"}

// skipFull names what to leave out when packing a directory that is not a git
// checkout: repository plumbing and local tooling state, neither of which is
// part of UAC.
var skipFull = map[string]bool{
	".git":    true,
	".claude": true,
	".vscode": true,
	".idea":   true,
}

func main() {
	var (
		uacDir = flag.String("uac", "", "path to the UAC repository (required for -mode full)")
		from   = flag.String("from", "", "full archive to derive from (required for -mode data)")
		out    = flag.String("out", "", "archive to write (required)")
		mode   = flag.String("mode", "", "full: the whole UAC tree, for the differential harness; data: the definitions the binary ships, derived from a full archive")
	)
	flag.Parse()

	if *out == "" {
		fmt.Fprintln(os.Stderr, "gen: -out is required")
		os.Exit(2)
	}

	var entries []entry
	var err error
	switch *mode {
	case "full":
		if *uacDir == "" {
			fmt.Fprintln(os.Stderr, "gen: -mode full requires -uac")
			os.Exit(2)
		}
		entries, err = fromCheckout(*uacDir)
	case "data":
		if *from == "" {
			fmt.Fprintln(os.Stderr, "gen: -mode data requires -from (the full archive it is derived from);\n"+
				"     run: go generate ./test/uacfull ./internal/uacdata")
			os.Exit(2)
		}
		entries, err = fromArchive(*from)
	default:
		fmt.Fprintf(os.Stderr, "gen: -mode must be full or data, got %q\n", *mode)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen: %v\n", err)
		os.Exit(1)
	}
	if err := write(entries, *out); err != nil {
		fmt.Fprintf(os.Stderr, "gen: %v\n", err)
		os.Exit(1)
	}
}

type entry struct {
	name string
	data []byte
	exec bool
}

// isData reports whether a path belongs in the definitions archive.
func isData(name string) bool {
	if name == "VERSION" {
		return true
	}
	for _, sub := range dataSubtrees {
		if strings.HasPrefix(name, sub+"/") {
			return true
		}
	}
	return false
}

// fromArchive reads a full archive and keeps only the parts uacscan reads.
// Provenance rides along untouched, so the two archives can never disagree
// about which UAC they came from.
func fromArchive(path string) ([]entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (run: go generate ./test/uacfull first)", path, err)
	}
	defer f.Close()

	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer zr.Close()

	var entries []entry
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if hdr.Typeflag != tar.TypeReg || !isData(hdr.Name) {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", path, hdr.Name, err)
		}
		// Definitions are data; nothing in them is executable.
		entries = append(entries, entry{name: hdr.Name, data: data})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s contains no artifact definitions", path)
	}
	return entries, nil
}

// fromCheckout packs a whole UAC repository.
//
// When the source is a git checkout the file list comes from git itself rather
// than from walking the directory. That is the only way to pack exactly what
// UAC is: a plain walk also picks up whatever local state happens to be lying
// around -- editor directories, tool configuration -- which does not belong in
// the archive and, because it changes as you work, quietly destroys
// reproducibility.
func fromCheckout(uacDir string) ([]entry, error) {
	version, commit := provenance(uacDir)

	var entries []entry

	// A VERSION file rides along so a collection can always be traced back to
	// the artifact definitions that produced it. For a forensic tool that
	// provenance is not optional.
	entries = append(entries, entry{
		name: "VERSION",
		data: []byte(fmt.Sprintf("uac_version=%s\nuac_commit=%s\n", version, commit)),
	})

	if tracked, err := gitFiles(uacDir); err == nil {
		for _, rel := range tracked {
			p := filepath.Join(uacDir, filepath.FromSlash(rel))
			info, err := os.Lstat(p)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry{
				name: rel,
				data: data,
				exec: info.Mode()&0111 != 0,
			})
		}
		return entries, nil
	}

	// Not a git checkout -- an extracted release tarball, say. Fall back to a
	// walk with an explicit denylist.
	for _, sub := range []string{"."} {
		root := filepath.Join(uacDir, sub)
		if _, err := os.Stat(root); err != nil {
			return nil, fmt.Errorf("%s: %w", root, err)
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, rerr := filepath.Rel(uacDir, p)
			if rerr != nil {
				return rerr
			}
			rel = filepath.ToSlash(rel)
			if skipFull[strings.SplitN(rel, "/", 2)[0]] {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			// The executable bit is the only mode detail that matters: the
			// harness runs ./uac and UAC runs the tools in bin/.
			entries = append(entries, entry{
				name: rel,
				data: data,
				exec: info.Mode()&0111 != 0,
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// write emits a deterministic archive.
func write(entries []entry, out string) error {
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
		mode := int64(0644)
		if e.exec {
			mode = 0755
		}
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     mode,
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
	execs := 0
	for _, e := range entries {
		if e.exec {
			execs++
		}
	}
	fmt.Printf("packed %d files (%d executable, %.1f KiB) into %s (%.1f KiB)\n",
		len(entries), execs, float64(total)/1024, out, float64(fi.Size())/1024)
	return nil
}

// gitFiles lists the files git tracks in dir, or an error if dir is not a
// checkout.
func gitFiles(dir string) ([]string, error) {
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, name := range strings.Split(string(out), "\x00") {
		if name != "" {
			files = append(files, name)
		}
	}
	if len(files) == 0 {
		return nil, errors.New("no tracked files")
	}
	return files, nil
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

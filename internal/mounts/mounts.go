// Package mounts reads the mount table, so that artifacts declaring
// exclude_file_system can be honoured.
//
// UAC's shipped configuration excludes network and pseudo filesystems --
// nfs, cifs, sysfs, fuse and friends -- and several artifacts exclude proc on
// their own. Without this, a live bodyfile walks into /proc and a collection on
// a machine with an NFS mount silently tries to traverse the network.
//
// It matters far less offline, where a mounted image usually has no pseudo
// filesystems inside it and the device-boundary check already stops the walk at
// the edge. It is a live-collection correctness fix more than an offline one.
package mounts

import (
	"bufio"
	"os"
	"sort"
	"strings"
)

// Mount is one entry from the mount table.
type Mount struct {
	Point  string // mount point, as the kernel reports it
	FSType string // filesystem type, e.g. proc, sysfs, nfs4
	Source string // device or remote path
}

// Table is the parsed mount table.
type Table []Mount

// PointsForTypes returns the mount points whose filesystem type is named in
// types, deepest first so that a nested mount is pruned before its parent.
//
// Matching is case-insensitive because the names artifacts use do not always
// match the kernel's spelling, and a "proc"/"procfs" pair appears in the corpus.
func (t Table) PointsForTypes(types []string) []string {
	if len(types) == 0 {
		return nil
	}
	want := make(map[string]bool, len(types))
	for _, ty := range types {
		want[strings.ToLower(strings.TrimSpace(ty))] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range t {
		if !want[strings.ToLower(m.FSType)] || seen[m.Point] {
			continue
		}
		seen[m.Point] = true
		out = append(out, m.Point)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

// Under narrows the table to mounts at or beneath root, returning their points
// relative to it.
//
// Collecting from a mounted image means the interesting mounts are the ones
// inside it; the examiner's own /proc is irrelevant and its path would not even
// be meaningful in the output, which records image-relative paths.
func (t Table) Under(root string) Table {
	root = strings.TrimSuffix(root, "/")
	if root == "" {
		return t
	}
	var out Table
	for _, m := range t {
		switch {
		case m.Point == root:
			out = append(out, Mount{Point: "/", FSType: m.FSType, Source: m.Source})
		case strings.HasPrefix(m.Point, root+"/"):
			out = append(out, Mount{Point: m.Point[len(root):], FSType: m.FSType, Source: m.Source})
		}
	}
	return out
}

// Load reads the running system's mount table. An empty table is not an error:
// the platform may not expose one, in which case exclude_file_system simply
// cannot be applied and the walk proceeds.
func Load() Table {
	if t := parseProcMounts("/proc/self/mounts"); len(t) > 0 {
		return t
	}
	return parseProcMounts("/etc/mtab")
}

// parseProcMounts reads the fstab-shaped table Linux exposes.
func parseProcMounts(path string) Table {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out Table
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		out = append(out, Mount{
			Source: unescape(fields[0]),
			Point:  unescape(fields[1]),
			FSType: fields[2],
		})
	}
	return out
}

// unescape decodes the octal escapes the kernel uses for spaces and tabs in
// mount points.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var v int
			ok := true
			for _, c := range s[i+1 : i+4] {
				if c < '0' || c > '7' {
					ok = false
					break
				}
				v = v*8 + int(c-'0')
			}
			if ok {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

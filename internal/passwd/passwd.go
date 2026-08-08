// Package passwd reads the account databases out of the image being examined,
// rather than the host's.
//
// This is the difference between correct and meaningless results for the
// no_user and no_group artifacts. find(1) answers -nouser by consulting the
// account database of the machine it runs on, so on a mounted image every file
// owned by a UID that happens not to exist on the examiner's workstation looks
// orphaned. UAC's own bodyfile2filelists.sh gets this right by reading the
// image's passwd file with awk; this does the same.
package passwd

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// DB is the account information read from one image.
type DB struct {
	UIDs  map[uint32]bool
	GIDs  map[uint32]bool
	Homes []string // deduplicated, sorted, for %user_home% expansion

	// ShellHomes is the subset belonging to accounts with a login shell, which
	// is what exclude_nologin_users selects.
	ShellHomes []string
}

var nologinShells = map[string]bool{
	"/bin/false": true, "/usr/bin/false": true,
	"/sbin/nologin": true, "/usr/sbin/nologin": true,
	"/bin/sync": true, "/usr/bin/sync": true,
	"": true,
}

// Load reads <root>/etc/passwd and <root>/etc/group. Missing files are not an
// error: an image may be partial, and the walk should still run.
func Load(root string) *DB {
	db := &DB{UIDs: map[uint32]bool{}, GIDs: map[uint32]bool{}}

	homes := map[string]bool{}
	shellHomes := map[string]bool{}
	for _, rel := range []string{"etc/passwd", "private/etc/passwd"} {
		forEachField(filepath.Join(root, rel), func(f []string) {
			if len(f) < 7 {
				return
			}
			if uid, err := strconv.ParseUint(f[2], 10, 32); err == nil {
				db.UIDs[uint32(uid)] = true
			}
			home := strings.TrimSuffix(f[5], "/")
			if home == "" || home == "/" || home == "/nonexistent" || home == "/dev/null" {
				return
			}
			homes[home] = true
			if !nologinShells[f[6]] {
				shellHomes[home] = true
			}
		})
	}
	for _, rel := range []string{"etc/group", "private/etc/group"} {
		forEachField(filepath.Join(root, rel), func(f []string) {
			if len(f) < 3 {
				return
			}
			if gid, err := strconv.ParseUint(f[2], 10, 32); err == nil {
				db.GIDs[uint32(gid)] = true
			}
		})
	}

	db.Homes = sortedKeys(homes)
	db.ShellHomes = sortedKeys(shellHomes)
	return db
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func forEachField(path string, fn func([]string)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fn(strings.Split(line, ":"))
	}
}

// Known reports whether the database was populated at all. When it is empty
// (no passwd file found) the no_user and no_group rules cannot be evaluated
// meaningfully, and callers should say so rather than reporting every file as
// orphaned.
func (d *DB) Known() bool { return len(d.UIDs) > 0 }

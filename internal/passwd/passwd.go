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
	"bytes"
	"maps"
	"slices"
	"strconv"
	"strings"

	"uacscan/internal/fsref"
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

// nonInteractiveShells are the shells UAC's get_user_home_list.sh excludes.
//
// They are matched as suffixes on purpose: an exact list of paths misses
// /usr/local/bin/false, /usr/local/sbin/nologin and every other packaging
// variant, which would leave service accounts in a collection that asked for
// them to be left out.
var nonInteractiveShells = []string{"false", "halt", "nologin", "shutdown", "sync", "git-shell"}

// isInteractiveShell reports whether a passwd shell field belongs to an account
// someone can log in as. An empty field is not one.
func isInteractiveShell(shell string) bool {
	shell = strings.TrimSpace(shell)
	if shell == "" {
		return false
	}
	for _, s := range nonInteractiveShells {
		if strings.HasSuffix(shell, s) {
			return false
		}
	}
	return true
}

// Load reads <root>/etc/passwd and <root>/etc/group. Missing files are not an
// error: an image may be partial, and the walk should still run.
func Load(root string) *DB {
	db := &DB{UIDs: map[uint32]bool{}, GIDs: map[uint32]bool{}}

	homes := map[string]bool{}
	shellHomes := map[string]bool{}
	for _, rel := range []string{"/etc/passwd", "/private/etc/passwd"} {
		forEachField(root, rel, func(f []string) {
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
			if isInteractiveShell(f[6]) {
				shellHomes[home] = true
			}
		})
	}
	for _, rel := range []string{"/etc/group", "/private/etc/group"} {
		forEachField(root, rel, func(f []string) {
			if len(f) < 3 {
				return
			}
			if gid, err := strconv.ParseUint(f[2], 10, 32); err == nil {
				db.GIDs[uint32(gid)] = true
			}
		})
	}

	db.Homes = slices.Sorted(maps.Keys(homes))
	db.ShellHomes = slices.Sorted(maps.Keys(shellHomes))
	return db
}

// forEachField reads through fsref.ReadBeneath rather than os.Open: the
// account database is inside the image, and a hostile image can point it at the
// examiner's own passwd file or at a FIFO.
func forEachField(root, rel string, fn func([]string)) {
	b, err := fsref.ReadBeneath(root, rel)
	if err != nil {
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fn(strings.Split(line, ":"))
	}
}

// KnownUsers and KnownGroups are answered separately.
//
// They come from different files, and either can be missing on its own. Gating
// both on the passwd file alone means an image with a passwd but no group file
// marks every file no_group, while one with a group but no passwd disables
// no_group entirely -- opposite errors from the same conflation.
func (d *DB) KnownUsers() bool  { return len(d.UIDs) > 0 }
func (d *DB) KnownGroups() bool { return len(d.GIDs) > 0 }

// Known reports whether anything at all was read.
func (d *DB) Known() bool { return d.KnownUsers() || d.KnownGroups() }

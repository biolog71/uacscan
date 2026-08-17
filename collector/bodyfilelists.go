package collector

import (
	"strings"
	"syscall"

	"uacscan/internal/spool"
)

// bodyfileListsCollector is the native reimplementation of UAC's own
// bin/bodyfile2filelists.sh. See rules.KindBodyfileLists for why this exists
// as a native collector rather than being left out of scope like every other
// command collector.
//
// The categorisation is applied per file during the walk rather than as a
// second pass over a written bodyfile, which needs no extra I/O and fits the
// same "one walk, every answer" design the rest of this project follows --
// ironically the exact idea bodyfile2filelists.sh itself embodies, just
// reading a file UAC had to write first instead of a live stream.
type bodyfileListsCollector struct {
	base
	writers map[string]*spool.Writer // output filename -> writer
}

func (c *bodyfileListsCollector) InspectFile(path string) error {
	f, err := c.ctx.ref(path)
	if err != nil {
		c.ctx.RecordError(path, "bodyfile_lists", err)
		return nil
	}

	isFile := f.IsRegular()
	isDir := f.IsDir()

	if f.IsSocket() {
		if err := c.emit("socket_files.txt", f.Path); err != nil {
			return err
		}
	}

	// A hidden entry is one whose basename starts with ".". The walker never
	// visits the "." and ".." pseudo-entries a raw find could, so there is no
	// need to exclude them separately here.
	if hidden := strings.HasPrefix(f.Name, "."); hidden {
		if isFile {
			if err := c.emit("hidden_files.txt", f.Path); err != nil {
				return err
			}
		}
		if isDir {
			if err := c.emit("hidden_directories.txt", f.Path); err != nil {
				return err
			}
		}
	}

	perm := f.Perm() // includes setuid/setgid/sticky, which is what is checked below
	if isFile && perm&syscall.S_ISUID != 0 {
		if err := c.emit("suid.txt", f.Path); err != nil {
			return err
		}
	}
	if isFile && perm&syscall.S_ISGID != 0 {
		if err := c.emit("sgid.txt", f.Path); err != nil {
			return err
		}
	}

	const (
		otherWrite = 0002
		groupWrite = 0020
	)
	othersWrite := perm&otherWrite != 0
	groupWritable := perm&groupWrite != 0
	sticky := perm&syscall.S_ISVTX != 0

	if othersWrite {
		if isFile {
			if err := c.emit("world_writable_files.txt", f.Path); err != nil {
				return err
			}
		}
		if isDir {
			if err := c.emit("world_writable_directories.txt", f.Path); err != nil {
				return err
			}
			if !sticky {
				if err := c.emit("world_writable_not_sticky_directories.txt", f.Path); err != nil {
					return err
				}
			}
		}
	}
	if groupWritable {
		if isFile {
			if err := c.emit("group_writable_files.txt", f.Path); err != nil {
				return err
			}
		}
		if isDir {
			if err := c.emit("group_writable_directories.txt", f.Path); err != nil {
				return err
			}
		}
	}

	// An owner that is not in the image's own account database is
	// unresolvable, not orphaned -- matching the no_user/no_group semantics
	// used everywhere else in this codebase. A nil map means no account
	// database was found at all, in which case the honest answer is "cannot
	// tell", not "everything is unknown". bodyfile2filelists.sh itself gets
	// this wrong: an empty passwd file leaves its uids array empty, so every
	// single file would come out "unknown". That failure mode is not worth
	// reproducing.
	if c.ctx.Env.UIDs != nil && !c.ctx.Env.UIDs[f.UID] {
		if isFile {
			if err := c.emit("user_name_unknown_files.txt", f.Path); err != nil {
				return err
			}
		}
		if isDir {
			if err := c.emit("user_name_unknown_directories.txt", f.Path); err != nil {
				return err
			}
		}
	}
	if c.ctx.Env.GIDs != nil && !c.ctx.Env.GIDs[f.GID] {
		if isFile {
			if err := c.emit("group_name_unknown_files.txt", f.Path); err != nil {
				return err
			}
		}
		if isDir {
			if err := c.emit("group_name_unknown_directories.txt", f.Path); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *bodyfileListsCollector) emit(name, path string) error {
	if c.writers == nil {
		c.writers = map[string]*spool.Writer{}
	}
	w, ok := c.writers[name]
	if !ok {
		var err error
		w, err = c.ctx.Store.Open(c.rule.ID, "bodyfile_lists", c.rule.OutputDir, name)
		if err != nil {
			return err
		}
		c.writers[name] = w
	}
	return w.WriteLine(path)
}

func (c *bodyfileListsCollector) Flush() error {
	for _, w := range c.writers {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func (c *bodyfileListsCollector) ScanResults() (any, error) {
	return c.streamSpool(), nil
}

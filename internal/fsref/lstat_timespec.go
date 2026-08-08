//go:build darwin || freebsd || netbsd

package fsref

import (
	"syscall"
	"time"
)

// fillTimes reads the timestamps from a stat buffer.
//
// Darwin and the BSDs that follow it name these fields Atimespec/Mtimespec/
// Ctimespec, and they report a birth time straight from lstat -- no statx
// needed -- so the bodyfile's crtime column is populated on macOS without a
// second syscall. Linux is the odd one out in needing statx for that.
func (f *FileRef) fillTimes(st *syscall.Stat_t) {
	f.Atime = time.Unix(int64(st.Atimespec.Sec), int64(st.Atimespec.Nsec))
	f.Mtime = time.Unix(int64(st.Mtimespec.Sec), int64(st.Mtimespec.Nsec))
	f.Ctime = time.Unix(int64(st.Ctimespec.Sec), int64(st.Ctimespec.Nsec))
	f.Btime = time.Unix(int64(st.Birthtimespec.Sec), int64(st.Birthtimespec.Nsec))
	f.HasBtime = true
}

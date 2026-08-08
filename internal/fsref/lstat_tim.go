//go:build !darwin && !freebsd && !netbsd

package fsref

import (
	"syscall"
	"time"
)

// fillTimes reads the timestamps from a stat buffer.
//
// Linux, OpenBSD, Solaris and AIX call these fields Atim/Mtim/Ctim. The int64
// conversions matter: on 32-bit targets the members are int32.
//
// None of these carries a birth time here. On Linux that is not a loss --
// Resolve tries statx first and only falls back to lstat when statx is
// unavailable, in which case crtime genuinely cannot be had.
func (f *FileRef) fillTimes(st *syscall.Stat_t) {
	f.Atime = time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec))
	f.Mtime = time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec))
	f.Ctime = time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec))
}

//go:build darwin || freebsd

package mounts

import "syscall"

// mntNoWait asks getfsstat for cached values rather than making it query every
// filesystem. A collection must not stall because an unresponsive network mount
// is being interrogated.
const mntNoWait = 2

// loadNative reads the mount table through getfsstat, which is how Darwin and
// FreeBSD expose it -- there is no /proc/self/mounts to parse.
//
// Without this, exclude_file_system could only be honoured on Linux. That
// matters most for a live collection: a workstation with an NFS or SMB mount
// would otherwise have the walk wander onto the network.
//
// NetBSD and OpenBSD are deliberately absent. The standard library either does
// not wrap the call there or names the struct fields differently, and guessing
// at an ABI that cannot be tested from here would be worse than leaving the
// exclusion unapplied and documenting it.
func loadNative() Table {
	n, err := syscall.Getfsstat(nil, mntNoWait)
	if err != nil || n == 0 {
		return nil
	}
	buf := make([]syscall.Statfs_t, n)
	n, err = syscall.Getfsstat(buf, mntNoWait)
	if err != nil {
		return nil
	}
	out := make(Table, 0, n)
	for _, fs := range buf[:n] {
		out = append(out, Mount{
			Point:  cstr(fs.Mntonname[:]),
			Source: cstr(fs.Mntfromname[:]),
			FSType: cstr(fs.Fstypename[:]),
		})
	}
	return out
}

// cstr converts a fixed-width NUL-terminated field to a string. The element
// type differs between Darwin and FreeBSD, hence the constraint.
func cstr[T int8 | uint8](b []T) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

//go:build linux

package collector

import (
	"syscall"
	"unsafe"
)

// getxattr reads one extended attribute without following symlinks.
//
// This is how the getcap artifact is implemented: a file capability is the
// security.capability attribute, so there is no need to shell out to getcap(8)
// once per candidate file.
//
// The raw syscall is used because the standard library only exposes Getxattr,
// which follows symlinks. Everything else in this walk uses lstat semantics and
// this must not be the exception -- a symlink pointing at a capability-bearing
// binary is not itself capability-bearing.
// maxXattrValue bounds the retry. The kernel caps an attribute value at 64 KiB,
// so a buffer of that size cannot be too small for a real one.
const maxXattrValue = 64 << 10

func getxattr(path, attr string) ([]byte, error) {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}
	a, err := syscall.BytePtrFromString(attr)
	if err != nil {
		return nil, err
	}
	// 128 bytes holds any real security.capability value; the retry exists so
	// that an unexpectedly large attribute is read in full rather than
	// silently truncated into a misparsed capability set.
	for size := 128; ; size *= 2 {
		buf := make([]byte, size)
		n, _, errno := syscall.Syscall6(syscall.SYS_LGETXATTR,
			uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(a)),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
		if errno == 0 {
			return buf[:n], nil
		}
		if errno != syscall.ERANGE || size >= maxXattrValue {
			return nil, errno
		}
	}
}

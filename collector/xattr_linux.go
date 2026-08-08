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
func getxattr(path, attr string) ([]byte, error) {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}
	a, err := syscall.BytePtrFromString(attr)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 128)
	n, _, errno := syscall.Syscall6(syscall.SYS_LGETXATTR,
		uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(a)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if errno != 0 {
		return nil, errno
	}
	return buf[:n], nil
}

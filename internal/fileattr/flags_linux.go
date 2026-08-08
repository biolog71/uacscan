//go:build linux

package fileattr

import (
	"syscall"
	"unsafe"
)

// fsIocGetFlags is FS_IOC_GETFLAGS: _IOR('f', 1, long).
const fsIocGetFlags = 0x80086601

// GetFlags reads a file's attribute flags, the same value lsattr reports.
//
// This needs an open descriptor, which the rest of the walk deliberately avoids.
// It is only reached for files already known to carry the immutable attribute
// -- statx answers that without opening anything -- so the open happens for a
// handful of files rather than for every inode.
func GetFlags(path string) (uint32, error) {
	fd, err := syscall.Open(path,
		syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	var flags int
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), uintptr(fsIocGetFlags), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return 0, errno
	}
	return uint32(flags), nil
}

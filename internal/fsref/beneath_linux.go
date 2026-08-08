//go:build linux

package fsref

import (
	"fmt"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// openat2 and the resolve flags that make it useful here. See openat2(2).
const (
	sysOpenat2 = 437

	resolveNoMagiclinks = 0x02
	resolveBeneath      = 0x08

	oPath = 0x200000 // O_PATH: resolve the name without opening the object
)

// openHow is struct open_how from linux/openat2.h.
type openHow struct {
	Flags   uint64
	Mode    uint64
	Resolve uint64
}

// openat2Unavailable latches once the kernel turns out not to have the syscall,
// so a scan of a million files does not make a million failing syscalls.
var openat2Unavailable atomic.Bool

// checkBeneathKernel asks the kernel to resolve rel under root with
// RESOLVE_BENEATH, which fails the resolution outright if any component would
// leave root -- through a symlink, a magic link, or "..".
//
// This is stronger than checking the ancestors with lstat: the whole path is
// resolved in one atomic operation, so there is no window between checking one
// component and moving to the next, and it covers /proc magic links that lstat
// cannot see. It needs Linux 5.6, so a kernel without it reports false and the
// caller falls back to the portable check.
//
// The descriptor is closed immediately: this is a containment check, not the
// handle the read is done through. A window therefore remains between the check
// and the subsequent open by path -- irrelevant for a static, read-only image,
// and closing it would mean threading descriptors through the whole content
// path.
func checkBeneathKernel(root, rel string) (checked bool, err error) {
	if openat2Unavailable.Load() {
		return false, nil
	}

	rootFd, err := syscall.Open(strings.TrimSuffix(root, "/"),
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer syscall.Close(rootFd)

	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return true, nil
	}
	p, err := syscall.BytePtrFromString(rel)
	if err != nil {
		return false, err
	}

	how := openHow{
		// O_PATH|O_NOFOLLOW: the leaf may legitimately be a symlink, and it is
		// recorded rather than followed. Only the path to it must stay inside.
		Flags:   uint64(oPath | syscall.O_NOFOLLOW | syscall.O_CLOEXEC),
		Resolve: resolveBeneath | resolveNoMagiclinks,
	}
	fd, _, errno := syscall.Syscall6(sysOpenat2,
		uintptr(rootFd), uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)

	switch errno {
	case 0:
		syscall.Close(int(fd))
		return true, nil
	case syscall.ENOSYS, syscall.EINVAL, syscall.EPERM:
		// Too old a kernel, or a seccomp policy that refuses it.
		openat2Unavailable.Store(true)
		return false, nil
	case syscall.EXDEV, syscall.ELOOP:
		// Exactly what this exists to catch: the path would leave root.
		return true, fmt.Errorf("%w: %s leaves the collection root", ErrEscapesRoot, rel)
	case syscall.ENOENT, syscall.ENOTDIR:
		// The target simply is not there; Resolve reports that properly.
		return true, nil
	default:
		return false, errno
	}
}

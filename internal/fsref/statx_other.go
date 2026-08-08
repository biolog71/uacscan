//go:build !linux

package fsref

// statx is a Linux syscall. Everywhere else Resolve falls through to lstat,
// which on Darwin and the BSDs also carries a birth time.
const sysStatx = 0

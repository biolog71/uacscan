//go:build !darwin && !freebsd

package mounts

// loadNative has no equivalent here. Linux is covered by /proc/self/mounts;
// NetBSD, OpenBSD, Solaris and AIX are not covered at all, so
// exclude_file_system cannot be applied there and the walk proceeds without it.
func loadNative() Table { return nil }

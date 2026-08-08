//go:build !linux || (!amd64 && !arm64)

package fsref

// sysStatx == 0 means "no statx on this platform"; Resolve falls back to lstat
// and simply reports no birth time and no immutable/append attributes.
const sysStatx = 0

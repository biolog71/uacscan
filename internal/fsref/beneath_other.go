//go:build !linux

package fsref

// checkBeneathKernel has no equivalent outside Linux: openat2's RESOLVE_BENEATH
// is the only interface that resolves a whole path atomically beneath a root.
// Reporting false makes the caller fall back to checking the ancestors with
// lstat, which is portable and reaches the same verdict.
func checkBeneathKernel(root, rel string) (bool, error) { return false, nil }

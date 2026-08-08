//go:build solaris || aix

package fixture

// mkfifo is a no-op where the standard library does not expose it. The fixture
// simply lacks a FIFO on those platforms; the walker is still exercised by the
// other special files.
func mkfifo(path string, mode uint32) error { return nil }

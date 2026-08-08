//go:build linux

package fsref

import "runtime"

// SYS_statx by architecture. statx landed in Linux 4.11 with a per-arch syscall
// number; there is no portable constant in the standard library, and getting it
// wrong on one architecture silently costs birth times and the immutable
// attribute rather than failing loudly -- which is exactly what happened to
// linux/386 when this was gated on amd64 and arm64 alone.
var sysStatx = map[string]uintptr{
	"amd64":    332,
	"386":      383,
	"arm64":    291,
	"arm":      397,
	"riscv64":  291,
	"ppc64":    383,
	"ppc64le":  383,
	"s390x":    379,
	"mips":     4366,
	"mipsle":   4366,
	"mips64":   5326,
	"mips64le": 5326,
	"loong64":  291,
}[runtime.GOARCH]

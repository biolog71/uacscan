// Package targetos identifies the operating system of the image being
// collected from, so that artifacts declaring supported_os can be filtered.
//
// UAC answers this with `uname -s`, which reports the *examiner's* system. That
// is correct on a live collection and wrong on a mounted image, which is why
// UAC makes you pass -s offline. Here the image is inspected for marker files
// instead, and the host is used only when collecting from / itself. An explicit
// flag still overrides everything.
package targetos

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// OS is one of the operating system names UAC's artifacts use in supported_os.
type OS string

const (
	AIX       OS = "aix"
	ESXi      OS = "esxi"
	FreeBSD   OS = "freebsd"
	Linux     OS = "linux"
	MacOS     OS = "macos"
	NetBSD    OS = "netbsd"
	NetScaler OS = "netscaler"
	OpenBSD   OS = "openbsd"
	Solaris   OS = "solaris"

	// Unknown means detection failed and no override was given.
	Unknown OS = ""
)

// All lists every value an artifact may name, for flag validation and help.
var All = []OS{AIX, ESXi, FreeBSD, Linux, MacOS, NetBSD, NetScaler, OpenBSD, Solaris}

// Valid reports whether s names a supported operating system.
func Valid(s string) bool {
	for _, o := range All {
		if OS(s) == o {
			return true
		}
	}
	return false
}

func Names() string {
	out := make([]string, 0, len(All))
	for _, o := range All {
		out = append(out, string(o))
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// marker is one piece of evidence that an image belongs to a given OS.
type marker struct {
	os   OS
	path string
}

// markers are checked in order, most specific first. NetScaler and ESXi come
// before the systems they are built on, because a NetScaler image is also a
// FreeBSD image and would otherwise be misidentified.
var markers = []marker{
	{NetScaler, "netscaler"},
	{NetScaler, "flash/nsconfig"},
	{ESXi, "vmfs"},
	{ESXi, "etc/vmware"},

	{MacOS, "System/Library/CoreServices/SystemVersion.plist"},
	{MacOS, "private/etc/passwd"},
	{MacOS, "Library/Preferences"},

	{Solaris, "etc/release"},
	{Solaris, "kernel/genunix"},

	{AIX, "usr/lpp"},
	{AIX, "etc/objrepos"},

	{NetBSD, "netbsd"},
	{OpenBSD, "bsd"},

	{FreeBSD, "bin/freebsd-version"},
	{FreeBSD, "boot/loader.conf"},

	{Linux, "etc/os-release"},
	{Linux, "etc/debian_version"},
	{Linux, "etc/redhat-release"},
	{Linux, "proc/version"},
	{Linux, "lib/systemd/systemd"},
	{Linux, "etc/fstab"},
}

// Detect identifies the operating system of the tree at root, returning the
// marker that decided it. An empty OS means nothing matched, which is common
// for a partial image or an arbitrary directory -- callers should fall back to
// the host rather than guessing.
func Detect(root string) (OS, string) {
	return DetectFS(os.DirFS(root))
}

// DetectFS is Detect over any filesystem, which is what makes it testable
// without building a fake image on disk.
func DetectFS(fsys fs.FS) (OS, string) {
	for _, m := range markers {
		if _, err := fs.Stat(fsys, m.path); err == nil {
			return m.os, m.path
		}
	}
	return Unknown, ""
}

// Host reports the operating system uacscan is running on, named the way UAC's
// artifacts do.
func Host() OS {
	switch runtime.GOOS {
	case "linux":
		return Linux
	case "darwin":
		return MacOS
	case "freebsd":
		return FreeBSD
	case "netbsd":
		return NetBSD
	case "openbsd":
		return OpenBSD
	case "aix":
		return AIX
	case "solaris", "illumos":
		return Solaris
	}
	return Unknown
}

// Resolve decides which operating system to filter artifacts against and
// explains how it got there, because that decision changes what is collected
// and belongs in the run log.
//
// An explicit override always wins. Collecting from / means the host is the
// image. Otherwise the image is inspected, and if that is inconclusive the
// result is Unknown -- never the examiner's own operating system.
//
// Assuming the host would be actively harmful: a partial macOS image examined
// on a Linux workstation would have every macOS artifact filtered out, and the
// collection would look complete. Unknown disables the filter instead, so an
// unidentified image is over-collected rather than silently under-collected.
func Resolve(override, mountPoint string) (OS, string, error) {
	if override != "" {
		if !Valid(override) {
			return Unknown, "", &InvalidOSError{Name: override}
		}
		return OS(override), "specified with -s", nil
	}
	if mountPoint == "" || mountPoint == "/" {
		return Host(), "running system (mount point is /)", nil
	}
	if got, evidence := Detect(mountPoint); got != Unknown {
		return got, "detected from " + filepath.Join(mountPoint, evidence), nil
	}
	return Unknown, "could not identify the image; collecting every artifact -- pass -s to narrow it", nil
}

// InvalidOSError reports an unusable -s value.
type InvalidOSError struct{ Name string }

func (e *InvalidOSError) Error() string {
	return "unsupported operating system " + e.Name + "; expected one of: " + Names()
}

// Supports reports whether an artifact declaring these supported_os values
// applies to target. An empty list means the artifact does not say, which UAC
// treats as applying everywhere.
func Supports(supported []string, target OS) bool {
	if len(supported) == 0 || target == Unknown {
		return true
	}
	for _, s := range supported {
		if s == "all" || OS(s) == target {
			return true
		}
	}
	return false
}

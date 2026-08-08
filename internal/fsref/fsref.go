// Package fsref resolves a path into the single metadata record every rule and
// collector reads from.
//
// The whole design rests on one invariant: a path is resolved exactly once per
// walk step, no matter how many rules examine it. Collectors never call stat
// themselves; they ask the Cache, which the walker has already primed.
package fsref

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	atFdCwd           int = -100
	atSymlinkNofollow     = 0x100

	statxAll = 0x00000fff

	maskBtime = 0x00000800

	// stx_attributes bits we care about; see statx(2).
	AttrCompressed = 0x00000004
	AttrImmutable  = 0x00000010
	AttrAppend     = 0x00000020
	AttrNodump     = 0x00000040
	AttrEncrypted  = 0x00000800
)

// FileRef is the resolved metadata for one path. It holds no file descriptor:
// an open descriptor would cost two extra syscalls per file, would pin the
// inode, and on a mounted image would risk opening the *host's* device nodes.
// Bytes are handled separately, by the content broker, and only for files some
// rule actually asked to read.
type FileRef struct {
	Path  string // image-relative, e.g. /etc/passwd -- this is what gets recorded
	Real  string // syscall path, e.g. /mnt/img/etc/passwd
	Name  string // basename
	Depth int    // 0 for the walk root

	RawMode uint16 // st_mode, type bits included
	Nlink   uint64
	UID     uint32
	GID     uint32
	Ino     uint64
	Dev     uint64
	Size    int64

	Atime time.Time
	Mtime time.Time
	Ctime time.Time
	Btime time.Time

	HasBtime  bool
	Attrs     uint64 // stx_attributes
	AttrsMask uint64 // which bits of Attrs the filesystem actually reports

	linkOnce bool
	linkVal  string
	linkErr  error
}

// Resolve stats one path. real is the path to hand the kernel; rel is the
// image-relative path to record.
func Resolve(real, rel string, depth int) (*FileRef, error) {
	f := &FileRef{
		Path:  rel,
		Real:  real,
		Name:  path.Base(rel),
		Depth: depth,
	}
	if sysStatx != 0 {
		if err := f.fillStatx(); err == nil {
			return f, nil
		} else if !errors.Is(err, syscall.ENOSYS) {
			return nil, &fs.PathError{Op: "statx", Path: real, Err: err}
		}
	}
	if err := f.fillLstat(); err != nil {
		return nil, &fs.PathError{Op: "lstat", Path: real, Err: err}
	}
	return f, nil
}

// statx buffer layout, from include/uapi/linux/stat.h. Offsets are fixed ABI.
const (
	offMask       = 0
	offAttributes = 8
	offNlink      = 16
	offUID        = 20
	offGID        = 24
	offMode       = 28
	offIno        = 32
	offSize       = 40
	offAttrsMask  = 56
	offAtime      = 64
	offBtime      = 80
	offCtime      = 96
	offMtime      = 112
	offDevMajor   = 128
	offDevMinor   = 132
)

func (f *FileRef) fillStatx() error {
	p, err := syscall.BytePtrFromString(f.Real)
	if err != nil {
		return err
	}
	var buf [256]byte
	// dirfd goes through a variable: uintptr(-100) is rejected as a constant
	// conversion, which is why the stdlib does the same dance.
	dirfd := atFdCwd
	_, _, e := syscall.Syscall6(uintptr(sysStatx),
		uintptr(dirfd), uintptr(unsafe.Pointer(p)),
		uintptr(atSymlinkNofollow), uintptr(statxAll),
		uintptr(unsafe.Pointer(&buf[0])), 0)
	if e != 0 {
		return e
	}
	le := binary.LittleEndian
	mask := le.Uint32(buf[offMask:])
	f.Attrs = le.Uint64(buf[offAttributes:])
	f.AttrsMask = le.Uint64(buf[offAttrsMask:])
	f.Nlink = uint64(le.Uint32(buf[offNlink:]))
	f.UID = le.Uint32(buf[offUID:])
	f.GID = le.Uint32(buf[offGID:])
	f.RawMode = le.Uint16(buf[offMode:])
	f.Ino = le.Uint64(buf[offIno:])
	f.Size = int64(le.Uint64(buf[offSize:]))
	f.Atime = statxTime(buf[offAtime:])
	f.Ctime = statxTime(buf[offCtime:])
	f.Mtime = statxTime(buf[offMtime:])
	if mask&maskBtime != 0 {
		f.Btime = statxTime(buf[offBtime:])
		f.HasBtime = true
	}
	major := uint64(le.Uint32(buf[offDevMajor:]))
	minor := uint64(le.Uint32(buf[offDevMinor:]))
	f.Dev = mkdev(major, minor)
	return nil
}

func statxTime(b []byte) time.Time {
	sec := int64(binary.LittleEndian.Uint64(b[0:8]))
	nsec := int64(binary.LittleEndian.Uint32(b[8:12]))
	return time.Unix(sec, nsec)
}

// mkdev matches glibc's makedev encoding, which is what st_dev uses.
func mkdev(major, minor uint64) uint64 {
	return (major&0xfffff000)<<32 | (major&0x00000fff)<<8 |
		(minor&0xffffff00)<<12 | (minor & 0x000000ff)
}

// fillLstat is the portable path, used wherever statx is unavailable. The
// timestamp fields are named differently on Darwin than everywhere else, so the
// per-OS half lives in lstat_darwin.go / lstat_other.go.
func (f *FileRef) fillLstat() error {
	var st syscall.Stat_t
	if err := syscall.Lstat(f.Real, &st); err != nil {
		return err
	}
	f.RawMode = uint16(st.Mode)
	f.Nlink = uint64(st.Nlink)
	f.UID = st.Uid
	f.GID = st.Gid
	f.Ino = st.Ino
	f.Dev = uint64(st.Dev)
	f.Size = st.Size
	f.fillTimes(&st)
	return nil
}

// File type helpers. These read the raw mode bits rather than converting to
// fs.FileMode, because the bodyfile output needs the exact POSIX type char.

func (f *FileRef) typeBits() uint16 { return f.RawMode & syscall.S_IFMT }

func (f *FileRef) IsRegular() bool { return f.typeBits() == syscall.S_IFREG }
func (f *FileRef) IsDir() bool     { return f.typeBits() == syscall.S_IFDIR }
func (f *FileRef) IsSymlink() bool { return f.typeBits() == syscall.S_IFLNK }
func (f *FileRef) IsFIFO() bool    { return f.typeBits() == syscall.S_IFIFO }
func (f *FileRef) IsSocket() bool  { return f.typeBits() == syscall.S_IFSOCK }
func (f *FileRef) IsBlockDev() bool {
	return f.typeBits() == syscall.S_IFBLK
}
func (f *FileRef) IsCharDev() bool { return f.typeBits() == syscall.S_IFCHR }

// TypeChar returns the find(1) -type letter for this file.
func (f *FileRef) TypeChar() byte {
	switch f.typeBits() {
	case syscall.S_IFREG:
		return 'f'
	case syscall.S_IFDIR:
		return 'd'
	case syscall.S_IFLNK:
		return 'l'
	case syscall.S_IFBLK:
		return 'b'
	case syscall.S_IFCHR:
		return 'c'
	case syscall.S_IFIFO:
		return 'p'
	case syscall.S_IFSOCK:
		return 's'
	}
	return '?'
}

// Perm returns the permission bits including setuid/setgid/sticky.
func (f *FileRef) Perm() uint16 { return f.RawMode & 07777 }

// Immutable reports whether the immutable flag is set, and whether the
// filesystem actually answered. statx gives us this without the
// FS_IOC_GETFLAGS ioctl, which would have required an open descriptor.
func (f *FileRef) Immutable() (set, known bool) {
	if f.AttrsMask&AttrImmutable == 0 {
		return false, false
	}
	return f.Attrs&AttrImmutable != 0, true
}

// Link returns the symlink target, resolved at most once.
func (f *FileRef) Link() (string, error) {
	if !f.linkOnce {
		f.linkOnce = true
		if f.IsSymlink() {
			f.linkVal, f.linkErr = os.Readlink(f.Real)
		}
	}
	return f.linkVal, f.linkErr
}

// ModeString renders permissions the way GNU stat's %A does, which is the
// format the mactime bodyfile expects.
func (f *FileRef) ModeString() string {
	var b [10]byte
	switch f.typeBits() {
	case syscall.S_IFREG:
		b[0] = '-'
	case syscall.S_IFDIR:
		b[0] = 'd'
	case syscall.S_IFLNK:
		b[0] = 'l'
	case syscall.S_IFBLK:
		b[0] = 'b'
	case syscall.S_IFCHR:
		b[0] = 'c'
	case syscall.S_IFIFO:
		b[0] = 'p'
	case syscall.S_IFSOCK:
		b[0] = 's'
	default:
		b[0] = '?'
	}
	m := f.RawMode
	rwx := func(off int, shift uint) {
		b[off] = dash(m&(0400>>shift) != 0, 'r')
		b[off+1] = dash(m&(0200>>shift) != 0, 'w')
		b[off+2] = dash(m&(0100>>shift) != 0, 'x')
	}
	rwx(1, 0)
	rwx(4, 3)
	rwx(7, 6)
	// setuid, setgid and sticky overload the execute column
	if m&syscall.S_ISUID != 0 {
		b[3] = pick(b[3] == 'x', 's', 'S')
	}
	if m&syscall.S_ISGID != 0 {
		b[6] = pick(b[6] == 'x', 's', 'S')
	}
	if m&syscall.S_ISVTX != 0 {
		b[9] = pick(b[9] == 'x', 't', 'T')
	}
	return string(b[:])
}

func dash(set bool, c byte) byte {
	if set {
		return c
	}
	return '-'
}

func pick(cond bool, a, b byte) byte {
	if cond {
		return a
	}
	return b
}

func (f *FileRef) String() string {
	return fmt.Sprintf("%s %s %d:%d %d", f.ModeString(), f.Path, f.UID, f.GID, f.Size)
}

// Cache is the single-entry memo that keeps InspectFile(path) from turning into
// one stat per rule. The walker primes it before dispatching a path, so every
// collector asking for the same path gets the already-resolved record. A miss
// is not an error -- it just means somebody called a collector outside a walk,
// so we resolve on demand and stay correct.
type Cache struct {
	cur  *FileRef
	root string // mount point, stripped when synthesising a miss
}

func NewCache(root string) *Cache { return &Cache{root: root} }

// Set primes the cache. Called by the walker, once per path.
func (c *Cache) Set(f *FileRef) { c.cur = f }

// Current returns the primed entry, if any.
func (c *Cache) Current() *FileRef { return c.cur }

// Get returns the record for path, resolving it only on a miss.
func (c *Cache) Get(path string) (*FileRef, error) {
	if c.cur != nil && (c.cur.Real == path || c.cur.Path == path) {
		return c.cur, nil
	}
	real, rel := path, path
	if c.root != "" && c.root != "/" {
		if strings.HasPrefix(path, c.root) {
			rel = Rel(path, c.root)
		} else {
			real = Join(c.root, path)
		}
	}
	return Resolve(real, rel, strings.Count(strings.Trim(rel, "/"), "/"))
}

// Hit reports whether Get(path) would avoid a syscall. Tests use it to assert
// the no-restat invariant.
func (c *Cache) Hit(path string) bool {
	return c.cur != nil && (c.cur.Real == path || c.cur.Path == path)
}

// Join prefixes an image-relative path with the mount point.
func Join(root, rel string) string {
	if root == "" || root == "/" {
		return rel
	}
	return strings.TrimSuffix(root, "/") + rel
}

// Rel strips the mount point, so recorded paths read /etc/passwd no matter
// where the image happened to be mounted.
func Rel(real, root string) string {
	if root == "" || root == "/" {
		return real
	}
	root = strings.TrimSuffix(root, "/")
	if real == root {
		return "/"
	}
	if strings.HasPrefix(real, root+"/") {
		return real[len(root):]
	}
	return real
}

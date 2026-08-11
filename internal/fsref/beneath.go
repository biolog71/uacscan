package fsref

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
)

// ErrEscapesRoot reports a path that would leave the tree it is supposed to
// stay inside.
var ErrEscapesRoot = fmt.Errorf("path escapes the collection root")

// CleanImagePath normalises a path taken from inside the image.
//
// Paths that come from a file's *contents* -- a HISTFILE assignment in an rc
// file, say -- are attacker-controlled on a hostile image. Interpreting them
// requires remembering that "/" means the image root, not the examiner's root,
// so "/../../etc/shadow" resolves back to "/etc/shadow" inside the image rather
// than climbing out of it. path.Clean does exactly that: leading ".." at the
// root are absorbed.
//
// A path that is not absolute is rejected: the shell would have resolved it
// against a working directory this walk does not have.
func CleanImagePath(p string) (string, error) {
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("%q is not absolute", p)
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("path contains a NUL byte")
	}
	cleaned := path.Clean(p)
	if !strings.HasPrefix(cleaned, "/") || strings.HasPrefix(cleaned, "/..") {
		return "", ErrEscapesRoot
	}
	return cleaned, nil
}

// ResolveBeneath stats an image-relative path while guaranteeing the result
// lies inside root.
//
// Cleaning the path is not enough on its own. The kernel follows symlinks in
// the intermediate components, so an image containing "/logs -> /" turns
// "<mount>/logs/etc/shadow" into the *examiner's* /etc/shadow -- and on a scan
// run as root that is a read of the host, or, once the same path reaches the
// copy destination, a write outside the output directory.
//
// On Linux the kernel is asked to resolve the path under the root with
// openat2's RESOLVE_BENEATH, which fails outright if any component would leave
// it -- through a symlink, a magic link, or "..". That is one atomic
// resolution rather than a sequence of separate checks.
//
// Where openat2 is unavailable -- an older kernel, or any other platform --
// every directory leading to the target is checked with lstat instead, and a
// symlinked one is refused.
//
// Either way this is a check followed by an open by path, so a window remains
// against something mutating the image mid-scan. That does not apply to the
// case it defends against: a forensic image is static, and mounted read-only
// if the examiner is doing it properly.
func ResolveBeneath(root, rel string) (*FileRef, error) {
	cleaned, err := containedPath(root, rel)
	if err != nil {
		return nil, err
	}
	return Resolve(Join(root, cleaned), cleaned, strings.Count(strings.Trim(cleaned, "/"), "/"))
}

// containedPath cleans rel and verifies it stays inside root, returning the
// cleaned image-relative path. The kernel answers first where openat2 exists;
// checkBeneath is the portable fallback.
//
// A root of "" or "/" is the examiner's own filesystem, where there is nothing
// to be contained within and no image to be hostile.
func containedPath(root, rel string) (string, error) {
	cleaned, err := CleanImagePath(rel)
	if err != nil {
		return "", err
	}
	if root == "" || root == "/" {
		return cleaned, nil
	}
	checked, err := checkBeneathKernel(root, cleaned)
	if err != nil {
		return "", err
	}
	if !checked {
		if err := checkBeneath(root, cleaned); err != nil {
			return "", err
		}
	}
	return cleaned, nil
}

// checkBeneath walks the components of rel below root, refusing any that is a
// symlink. The final component may be one -- it is never followed, only
// recorded -- so only the directories leading to it are checked.
func checkBeneath(root, rel string) error {
	base := strings.TrimSuffix(root, "/")
	parts := strings.Split(strings.Trim(rel, "/"), "/")

	current := base
	for i, name := range parts {
		if name == "" || name == "." {
			continue
		}
		if name == ".." {
			// Cleaning removed these; one surviving here means the caller
			// bypassed CleanImagePath.
			return ErrEscapesRoot
		}
		if i == len(parts)-1 {
			// The leaf itself may be a symlink: it is recorded, never followed.
			return nil
		}
		current += "/" + name

		fi, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // the target simply does not exist; Resolve will say so
			}
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s traverses the symbolic link %s",
				ErrEscapesRoot, rel, current)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%w: %s is not a directory", ErrEscapesRoot, current)
		}
	}
	return nil
}

// DestinationUnder joins a relative path onto a destination directory and
// verifies the result stays inside it.
//
// The copy destination is built from the same image-controlled path as the
// source, so it needs the same containment check. filepath.Join cleans, which
// means a path that climbed out would do so silently.
func DestinationUnder(dir, rel string) (string, error) {
	cleaned := path.Clean("/" + strings.TrimPrefix(rel, "/"))
	dst := path.Join(dir, cleaned)
	prefix := strings.TrimSuffix(dir, "/") + "/"
	if dst != strings.TrimSuffix(dir, "/") && !strings.HasPrefix(dst, prefix) {
		return "", fmt.Errorf("%w: %s", ErrEscapesRoot, rel)
	}
	return dst, nil
}

// CreateNoFollow creates a file for writing, refusing to follow a symlink that
// is already sitting at the destination.
//
// Without O_NOFOLLOW, a symlink left in the output tree -- by a previous run, or
// by anything else with write access to it -- would redirect a collected file
// somewhere else entirely.
func CreateNoFollow(path string, perm os.FileMode) (*os.File, error) {
	fd, err := syscall.Open(path,
		syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		uint32(perm))
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// MaxMetadataFile caps how much of an image file the metadata helpers will
// read. Hostnames and passwd files are small; anything larger is not one.
const MaxMetadataFile = 4 << 20

// OpenBeneath opens a regular file inside root for reading, without following
// symlinks and without blocking.
//
// The metadata helpers -- hostname, account database, OS markers -- read files
// chosen by the image, and a hostile image can make any of them a symlink to
// the examiner's filesystem or a FIFO that never opens. os.Open does both:
// follows the link, and blocks. So the path is contained first, the open is
// O_NOFOLLOW|O_NONBLOCK, and the result must be a regular file.
func OpenBeneath(root, rel string) (*os.File, error) {
	cleaned, err := containedPath(root, rel)
	if err != nil {
		return nil, err
	}
	full := Join(root, cleaned)

	fd, err := syscall.Open(full,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: full, Err: err}
	}
	f := os.NewFile(uintptr(fd), full)

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	// A FIFO opened O_NONBLOCK succeeds and then blocks on read; a device could
	// be worse. Only regular files carry the metadata these helpers want.
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, &os.PathError{Op: "open", Path: full,
			Err: fmt.Errorf("not a regular file (%s)", fi.Mode().Type())}
	}
	return f, nil
}

// ReadBeneath reads a metadata file from inside root, subject to the same
// containment and file-type rules as OpenBeneath and capped in size.
func ReadBeneath(root, rel string) ([]byte, error) {
	f, err := OpenBeneath(root, rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, MaxMetadataFile))
}

// ExistsBeneath reports whether rel names an existing regular file inside root.
// Used for the operating-system markers, where a symlink pointing out of the
// image must not count as evidence of anything.
func ExistsBeneath(root, rel string) bool {
	f, err := OpenBeneath(root, rel)
	if err != nil {
		return false
	}
	_ = f.Close() // opened read-only, purely to prove it exists
	return true
}

// DirExistsBeneath reports whether rel names an existing directory inside root.
func DirExistsBeneath(root, rel string) bool {
	cleaned, err := containedPath(root, rel)
	if err != nil {
		return false
	}
	fi, err := os.Lstat(Join(root, cleaned))
	return err == nil && fi.IsDir()
}

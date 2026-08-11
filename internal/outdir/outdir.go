// Package outdir names and creates the directory one collection writes into.
//
// Every run gets its own directory, created exclusively. That is what makes
// concurrent collections safe: two runs cannot be handed the same destination
// even if they start in the same second, so there is no lock to take, no lock
// to go stale, and no way for one collection's output to be interleaved into
// another's.
//
// It matters more than tidiness. The spool writers append in buffered chunks,
// and a flush boundary falls mid-line, so two processes appending to one
// bodyfile splice records from different images into each other -- with the
// right number of lines and no error, which is the worst way for evidence to be
// wrong. Unique directories remove the possibility rather than detecting it.
//
// The naming follows UAC's own convention, uac-%hostname%-%os%-%timestamp%, so
// the output is recognisable to anyone who knows the tool.
package outdir

import (
	"bufio"
	"bytes"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"time"

	"uacscan/internal/fsref"
	"uacscan/internal/spool"
)

// TimestampLayout is the 14-digit form UAC uses.
const TimestampLayout = "20060102150405"

// Name builds the run directory name.
func Name(hostname, targetOS string, now time.Time) string {
	if hostname == "" {
		hostname = "unknown"
	}
	if targetOS == "" {
		targetOS = "unknown"
	}
	return sanitize(fmt.Sprintf("uacscan-%s-%s-%s",
		hostname, targetOS, now.UTC().Format(TimestampLayout)))
}

// Create makes a uniquely named directory inside dest and returns its path.
//
// base names the directory; an empty base uses Name. If that directory already
// exists -- a second run in the same second, or a repeated explicit name -- a
// counter is appended until one is created. os.Mkdir fails rather than
// succeeding on an existing directory, so the winner of a race is whichever
// process created it, and the loser moves on to the next name.
func Create(dest, base string) (string, error) {
	if dest == "" {
		return "", fmt.Errorf("no destination directory given")
	}
	if err := os.MkdirAll(dest, spool.OutputDirPerm); err != nil {
		return "", err
	}
	base = sanitize(base)
	if base == "" {
		return "", fmt.Errorf("empty output directory name")
	}

	for attempt := 0; attempt < 1000; attempt++ {
		name := base
		if attempt > 0 {
			name = fmt.Sprintf("%s-%d", base, attempt+1)
		}
		path := filepath.Join(dest, name)
		err := os.Mkdir(path, spool.OutputDirPerm)
		if err == nil {
			return path, nil
		}
		if !os.IsExist(err) {
			return "", err
		}
	}
	return "", fmt.Errorf("could not create a unique directory under %s after 1000 attempts", dest)
}

// sanitize keeps the directory name usable on every platform UAC supports.
func sanitize(name string) string {
	name = strings.TrimSpace(name)
	repl := strings.NewReplacer(
		"/", "_", `\`, "_", "*", "_", "?", "_",
		":", "_", `"`, "_", "<", "_", ">", "_", "|", "_", " ", "_",
	)
	name = repl.Replace(name)
	for strings.Contains(name, "__") {
		name = strings.ReplaceAll(name, "__", "_")
	}
	return strings.Trim(name, "._-")
}

// Hostname reads the host name out of the image, falling back to the running
// system only when collecting from / itself.
//
// Reading it from the image is what makes the output directory identify the
// evidence rather than the workstation that processed it.
func Hostname(mountPoint string) string {
	if mountPoint == "" || mountPoint == "/" {
		if h, err := os.Hostname(); err == nil && h != "" {
			return h
		}
	}
	root := strings.TrimSuffix(mountPoint, "/")

	if h := firstLine(root, "/etc/hostname"); h != "" {
		return h
	}
	// FreeBSD and NetScaler keep it in rc.conf as hostname="name".
	if h := rcConfHostname(root, "/etc/rc.conf"); h != "" {
		return h
	}
	if h := firstLine(root, "/etc/myname"); h != "" { // OpenBSD
		return h
	}
	if h := firstLine(root, "/etc/nodename"); h != "" { // Solaris
		return h
	}
	return "unknown"
}

// lines reads a metadata file from inside the image and yields its trimmed
// lines.
//
// It goes through fsref.ReadBeneath rather than os.Open: the file is named by
// the image, and a hostile one can make it a symlink to the examiner's
// filesystem or a FIFO that never opens. An unreadable file yields nothing,
// which is what the callers want -- an absent hostname source is normal.
func lines(root, rel string) iter.Seq[string] {
	return func(yield func(string) bool) {
		b, err := fsref.ReadBeneath(root, rel)
		if err != nil {
			return
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			if !yield(strings.TrimSpace(sc.Text())) {
				return
			}
		}
	}
}

// firstLine returns the first line that is neither blank nor a comment.
func firstLine(root, rel string) string {
	for line := range lines(root, rel) {
		if line != "" && !strings.HasPrefix(line, "#") {
			return sanitize(line)
		}
	}
	return ""
}

// rcConfHostname reads hostname="name" out of an rc.conf.
//
// Commented lines are skipped: a disabled setting is not the configuration, and
// taking one would name the output directory after a host the image was not.
func rcConfHostname(root, rel string) string {
	for line := range lines(root, rel) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := strings.CutPrefix(line, "hostname="); ok {
			return sanitize(strings.Trim(strings.TrimSpace(v), `"'`))
		}
	}
	return ""
}

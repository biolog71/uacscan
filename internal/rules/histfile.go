package rules

import (
	"regexp"
	"strings"

	"uacscan/internal/fsref"
)

// UAC determines where a shell keeps its history by grepping the shell's rc
// files for a HISTFILE assignment and feeding the result to a second artifact
// as a file list. That is a genuine two-phase collection: the paths are not
// knowable until some file contents have been read.
//
// The producing step is a command collector, which cannot run offline. But the
// command itself is not arbitrary -- across all ten shell artifacts it is the
// same shape:
//
//	grep -E "^?VAR=.*" FILE... | sed -e 's|.*VAR=||' -e 's|^~/|HOME/|'
//
// so it can be recognised and performed natively while walking, without a
// shell. Anything that does not match this shape is left unimplemented rather
// than approximated.
var histfileCommand = regexp.MustCompile(
	`^grep -E "(\^?)([A-Z_]+)=\.\*"\s+(.+?)\s*\|\s*sed -e 's\|\.\*[A-Z_]+=\|\|'\s+-e 's\|\^~/\|(.*)/\|'$`)

// HistfileSpec describes a recognised extraction command.
type HistfileSpec struct {
	// Var is the variable assigned in the rc file, e.g. HISTFILE.
	Var string
	// Anchored means the assignment has to start the line.
	Anchored bool
	// Files are the rc files to read, with %user_home% still unexpanded.
	Files []string
	// HomePlaceholder is what a leading "~/" is rewritten to, which UAC always
	// sets to the user home being iterated.
	HomePlaceholder string
}

// ParseHistfileCommand recognises the HISTFILE extraction shape. The second
// return value reports whether the command was understood; false means the
// artifact is one this tool does not implement, which the caller should treat
// as "skip", not as "collected nothing".
func ParseHistfileCommand(cmd string) (HistfileSpec, bool) {
	m := histfileCommand.FindStringSubmatch(strings.TrimSpace(cmd))
	if m == nil {
		return HistfileSpec{}, false
	}
	files := splitFields(m[3])
	if len(files) == 0 {
		return HistfileSpec{}, false
	}
	return HistfileSpec{
		Anchored:        m[1] == "^",
		Var:             m[2],
		Files:           files,
		HomePlaceholder: m[4],
	}, true
}

func splitFields(s string) []string {
	var out []string
	for _, f := range strings.Fields(s) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// ExtractAssignments pulls the assigned values out of an rc file's contents,
// applying the same transformation the shell pipeline would: everything up to
// and including the last "VAR=" on the line is dropped.
func (s HistfileSpec) ExtractAssignments(content []byte) []string {
	var out []string
	needle := s.Var + "="
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimRight(line, "\r")
		idx := strings.Index(line, needle)
		if idx < 0 {
			continue
		}
		if s.Anchored && idx != 0 {
			continue
		}
		// sed 's|.*VAR=||' is greedy: it strips through the *last* occurrence.
		last := strings.LastIndex(line, needle)
		value := line[last+len(needle):]
		if v := cleanAssignment(value); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// cleanAssignment trims the quoting and trailing shell noise an rc file may
// carry around the value.
func cleanAssignment(v string) string {
	v = strings.TrimSpace(v)
	// Drop a trailing comment, then any trailing command separator.
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	v = strings.TrimRight(v, ";&")
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
	}
	return strings.TrimSpace(v)
}

// ResolveHistfile turns an extracted value into an absolute image path.
//
// UAC's sed rewrites a leading "~/" to the user home and leaves everything else
// alone, so a value that is neither absolute nor tilde-prefixed would reach cp
// as a relative path and fail. Rather than reproduce that failure, such values
// are reported as unresolvable and recorded, which at least leaves a trace that
// something was found and not collected.
//
// The value comes from inside the image and is therefore attacker-controlled on
// a hostile one. It is normalised before being returned, so that "/../../etc/
// shadow" means /etc/shadow inside the image rather than climbing out of it.
// Containment of the eventual filesystem access is enforced separately, by
// fsref.ResolveBeneath, because cleaning cannot see intermediate symlinks.
func ResolveHistfile(value, home string) (string, bool) {
	var raw string
	switch {
	case value == "":
		return "", false
	case strings.HasPrefix(value, "~/"):
		if home == "" {
			return "", false
		}
		raw = strings.TrimSuffix(home, "/") + value[1:]
	case strings.HasPrefix(value, "/"):
		raw = value
	default:
		// A relative path, or an unexpanded variable: the shell would have
		// resolved it against state this walk does not have.
		return "", false
	}
	cleaned, err := fsref.CleanImagePath(raw)
	if err != nil {
		return "", false
	}
	return cleaned, true
}

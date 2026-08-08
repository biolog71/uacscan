// Package artifact reads UAC artifact definition files.
//
// These files look like YAML but are not: UAC parses them with hand-rolled
// shell in lib/parse_artifact.sh, so they contain things no YAML library will
// accept -- bare scalars starting with '%' (path: %user_home%/.ssh), unquoted
// command values containing ": ", literal tabs inside descriptions. Rather than
// pre-mangling them into valid YAML and hoping the mangling is faithful, this
// parser accepts the dialect UAC actually uses.
package artifact

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// Doc is one artifact file: some document-level keys plus a list of entries.
type Doc struct {
	Source          string // path the document was read from
	Version         string
	OutputDirectory string
	Condition       string
	Artifacts       []Entry
}

// Entry is a single artifact definition. Unknown keys are kept in Extra rather
// than dropped, so a newer artifact file does not silently lose meaning.
type Entry struct {
	Source string // "files/system/etc.yaml"
	Index  int    // position within the file, for stable rule ids

	Description string
	SupportedOS []string
	Collector   string
	Condition   string

	Path               []string // may name several paths, shell-split
	PathPattern        []string
	NamePattern        []string
	ExcludePathPattern []string
	ExcludeNamePattern []string
	ExcludeFileSystem  []string
	FileType           []string
	Permissions        []string

	MaxDepth    int
	HasMaxDepth bool

	MinFileSize    int64
	HasMinFileSize bool
	MaxFileSize    int64
	HasMaxFileSize bool

	NoUser          bool
	NoGroup         bool
	IgnoreDateRange bool
	IsFileList      bool

	Command         string
	OutputFile      string
	OutputDirectory string

	ExcludeNologinUsers bool
	Foreach             string

	Extra map[string]string
}

// ID is a stable identifier used for rule names and spool file names.
func (e Entry) ID() string {
	return fmt.Sprintf("%s#%d", strings.TrimSuffix(e.Source, ".yaml"), e.Index)
}

// ParseFile reads one artifact file from disk.
func ParseFile(path, source string) (*Doc, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d, err := Parse(f, source)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	d.Source = source
	return d, nil
}

// Parse reads the artifact dialect from r. source names the document for error
// messages and rule ids.
func Parse(r io.Reader, source string) (*Doc, error) {
	doc := &Doc{Source: source}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	inArtifacts := false
	var cur *Entry

	flush := func() {
		if cur != nil {
			doc.Artifacts = append(doc.Artifacts, *cur)
			cur = nil
		}
	}

	line := 0
	for sc.Scan() {
		line++
		raw := strings.ReplaceAll(sc.Text(), "\t", " ")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// A list item starts a new entry. It may carry its first key inline.
		if trimmed == "-" || strings.HasPrefix(trimmed, "- ") {
			if !inArtifacts {
				// A list outside artifacts: ignore, but do not fail the file.
				continue
			}
			flush()
			cur = &Entry{Source: source, Index: len(doc.Artifacts)}
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			if rest == "" {
				continue
			}
			trimmed = rest
		}

		key, val, ok := splitKeyValue(trimmed)
		if !ok {
			// Not a key line. UAC ignores these; so do we, rather than
			// rejecting a file over a stray continuation.
			continue
		}

		if key == "artifacts" && cur == nil {
			inArtifacts = true
			continue
		}

		if cur != nil {
			if err := cur.set(key, val); err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			continue
		}

		switch key {
		case "version":
			doc.Version = val
		case "output_directory":
			doc.OutputDirectory = val
		case "condition":
			doc.Condition = val
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return doc, nil
}

// splitKeyValue finds the "key: value" break. It only accepts keys made of
// identifier characters, which is what keeps it from mistaking the colon inside
// a command value for a key separator.
func splitKeyValue(s string) (key, val string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return "", "", false
	}
	key = s[:i]
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", "", false
		}
	}
	return key, stripComment(strings.TrimSpace(s[i+1:])), true
}

// stripComment removes a trailing "# ..." comment, honouring quotes.
//
// UAC never strips these explicitly. It does not have to: the value is
// interpolated into a command string that gets eval'd, so an unquoted '#'
// becomes a shell comment and everything after it disappears. That is why
// "max_file_size: 1073741824 # 1GB" works at all. Reproducing the same rule
// here keeps us faithful to what UAC actually collects.
func stripComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#' && (i == 0 || s[i-1] == ' '):
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

func (e *Entry) set(key, val string) error {
	switch key {
	case "description":
		e.Description = unquote(val)
	case "supported_os":
		e.SupportedOS = parseList(val)
	case "collector":
		e.Collector = val
	case "condition":
		e.Condition = val
	case "path":
		e.Path = shellSplit(val)
	case "path_pattern":
		e.PathPattern = parseList(val)
	case "name_pattern":
		e.NamePattern = parseList(val)
	case "exclude_path_pattern":
		e.ExcludePathPattern = parseList(val)
	case "exclude_name_pattern":
		e.ExcludeNamePattern = parseList(val)
	case "exclude_file_system":
		e.ExcludeFileSystem = parseList(val)
	case "file_type":
		e.FileType = parseList(val)
	case "permissions":
		e.Permissions = parseList(val)
	case "max_depth":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("max_depth %q: %w", val, err)
		}
		e.MaxDepth, e.HasMaxDepth = n, true
	case "min_file_size":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return fmt.Errorf("min_file_size %q: %w", val, err)
		}
		e.MinFileSize, e.HasMinFileSize = n, true
	case "max_file_size":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return fmt.Errorf("max_file_size %q: %w", val, err)
		}
		e.MaxFileSize, e.HasMaxFileSize = n, true
	case "no_user":
		e.NoUser = val == "true"
	case "no_group":
		e.NoGroup = val == "true"
	case "ignore_date_range":
		e.IgnoreDateRange = val == "true"
	case "is_file_list":
		e.IsFileList = val == "true"
	case "exclude_nologin_users":
		e.ExcludeNologinUsers = val == "true"
	case "command":
		e.Command = val
	case "foreach":
		e.Foreach = val
	case "output_file":
		e.OutputFile = val
	case "output_directory":
		e.OutputDirectory = val
	default:
		if e.Extra == nil {
			e.Extra = map[string]string{}
		}
		e.Extra[key] = val
	}
	return nil
}

// parseList reads either a "[a, b, c]" flow list or a bare scalar.
func parseList(val string) []string {
	val = strings.TrimSpace(val)
	if !strings.HasPrefix(val, "[") {
		if val == "" {
			return nil
		}
		return []string{unquote(val)}
	}
	val = strings.TrimSuffix(strings.TrimPrefix(val, "["), "]")
	var out []string
	for _, part := range strings.Split(val, ",") {
		if p := unquote(strings.TrimSpace(part)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// shellSplit splits a path value on spaces the way the shell would when UAC
// evals the find command, so that %user_home%/Library/"Application Support"
// stays a single path.
func shellSplit(s string) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	started := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote = c
			started = true
		case c == ' ':
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	if started {
		out = append(out, cur.String())
	}
	return out
}

// LoadDir reads every *.yaml under a directory on disk.
func LoadDir(root string) ([]*Doc, map[string]error) {
	return LoadFS(os.DirFS(root))
}

// LoadFS reads every *.yaml in fsys, returning documents keyed by their path
// within it. Parse failures are returned per file rather than aborting the
// load, so one malformed artifact cannot take down a whole collection.
//
// Taking an fs.FS rather than a path is what lets the embedded corpus and a
// real UAC checkout run through exactly the same code: os.DirFS for one,
// the unpacked archive for the other.
func LoadFS(fsys fs.FS) ([]*Doc, map[string]error) {
	var docs []*Doc
	errs := map[string]error{}
	fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return nil
		}
		f, oerr := fsys.Open(p)
		if oerr != nil {
			errs[p] = oerr
			return nil
		}
		doc, perr := Parse(f, p)
		f.Close()
		if perr != nil {
			errs[p] = fmt.Errorf("%s: %w", p, perr)
			return nil
		}
		doc.Source = p
		docs = append(docs, doc)
		return nil
	})
	return docs, errs
}

// Package rules compiles UAC artifact entries into predicates evaluated during
// a single filesystem walk.
//
// UAC runs one find(1) per artifact entry. This package turns each entry into a
// Rule whose Match method answers the same question find would have answered,
// so ~490 separate traversals collapse into one.
package rules

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"uacscan/internal/artifact"
	"uacscan/internal/fsref"
	"uacscan/internal/mounts"
	"uacscan/internal/targetos"
)

// Kind is the collector action a rule triggers.
type Kind string

const (
	KindFile Kind = "file" // copy the bytes out
	KindFind Kind = "find" // record the path
	KindStat Kind = "stat" // emit a bodyfile line
	KindHash Kind = "hash" // digest the contents

	// KindList is not a UAC collector name. It is what a recognised
	// HISTFILE-extraction command compiles to: a rule that reads matching rc
	// files during the walk and contributes the paths it finds to a list some
	// is_file_list artifact then collects.
	KindList Kind = "list"
)

// IsOffline reports whether a collector name can run against a mounted image.
// The command collector cannot: it executes on the live system.
func IsOffline(collector string) bool {
	switch Kind(collector) {
	case KindFile, KindFind, KindStat, KindHash:
		return true
	}
	return false
}

// Env carries everything a rule needs that is not on the file itself.
type Env struct {
	MountPoint string
	Now        time.Time

	// OS is the operating system of the image being collected from, used to
	// skip artifacts that declare a supported_os not covering it. Unknown
	// disables the filter rather than dropping everything.
	OS targetos.OS

	// Date range, in days before Now. Zero disables, matching UAC.
	StartDateDays int
	EndDateDays   int

	// Which timestamps the date range tests. UAC's shipped config enables
	// mtime and ctime but *not* atime, so a file touched only by a read stays
	// out of range. Defaults here match that; see internal/config.
	EnableMtime bool
	EnableAtime bool
	EnableCtime bool

	// HashAlgorithm is the digest set the hash collector produces. UAC
	// defaults to md5 and sha1.
	HashAlgorithm []string

	// ExcludeNamePattern and MaxDepth come from uac.conf and apply to every
	// rule, on top of whatever an individual artifact asks for.
	ExcludeNamePattern []string
	MaxDepth           int

	// ShellUserHomes is the subset of UserHomes belonging to accounts with a
	// login shell, used by artifacts declaring exclude_nologin_users.
	ShellUserHomes []string

	// Account databases read from the *image*, not the host. This is what makes
	// no_user/no_group correct offline, where find(1) would consult the
	// examiner's own passwd file and report nonsense.
	UIDs map[uint32]bool
	GIDs map[uint32]bool

	// Mounts is the mount table, used to turn an artifact's
	// exclude_file_system into concrete paths to prune.
	Mounts mounts.Table

	// UserHomes expands %user_home%.
	UserHomes []string
	TempDir   string
	OutputDir string
}

// permTest is one find -perm argument.
type permTest struct {
	mode  uint16
	allOf bool // "-perm -MODE": every listed bit must be set
}

func parsePerm(s string) (permTest, error) {
	t := permTest{}
	if strings.HasPrefix(s, "-") {
		t.allOf = true
		s = s[1:]
	} else if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "+") {
		// "any of these bits"; UAC does not use it, but do not silently
		// misinterpret it as an exact match if an artifact starts to.
		return t, fmt.Errorf("unsupported -perm form %q", s)
	}
	v, err := strconv.ParseUint(s, 8, 16)
	if err != nil {
		return t, fmt.Errorf("bad permission %q: %w", s, err)
	}
	t.mode = uint16(v)
	return t, nil
}

func (t permTest) match(perm uint16) bool {
	if t.allOf {
		return perm&t.mode == t.mode
	}
	return perm == t.mode
}

// anchor is one expanded starting path -- the argument find would have been
// given. A file is in scope if it is the anchor itself or lives beneath it.
type anchor struct {
	glob  Glob
	depth int // number of separators in the anchor, for max_depth
}

// Rule is one compiled artifact entry.
type Rule struct {
	ID     string
	Source string
	Kind   Kind

	OutputDir  string
	OutputFile string

	anchors      []anchor
	pathPatterns []Glob
	namePatterns []Glob
	excludePath  []Glob
	excludeName  []Glob

	types map[byte]bool
	perms []permTest

	minSize, maxSize       int64
	hasMinSize, hasMaxSize bool

	maxDepth    int
	hasMaxDepth bool

	noUser, noGroup bool
	ignoreDateRange bool

	// Command is carried through for the two find+command artifacts, whose
	// per-file work (getcap, lsattr) the collectors implement natively.
	Command string

	// Histfile is set on KindList rules: what to extract and how.
	Histfile HistfileSpec

	// ListKey ties a producer to its consumer. On a KindList rule it is where
	// the list would have been written; on a file rule built from
	// is_file_list it is where the list is read from.
	ListKey string

	// FromList marks a rule whose paths come from a list produced during the
	// walk rather than from matching files as they are visited.
	FromList bool

	// Homes is the set of user home directories, needed to resolve a "~/"
	// value found in a system-wide rc file, where the owning user is not
	// implied by the path.
	Homes []string
}

// LiteralPrefixes returns the non-glob leading path prefixes of this rule's
// anchors. The walker uses them to skip whole subtrees no rule can match.
func (r *Rule) LiteralPrefixes() []string {
	out := make([]string, 0, len(r.anchors))
	for _, a := range r.anchors {
		p := a.glob.literal
		if a.glob.anyPos {
			return []string{"/"} // matches anywhere; nothing can be skipped
		}
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			p = p[:i+1]
		}
		out = append(out, p)
	}
	return out
}

// Excluded reports whether the path is pruned by this rule's own exclusions.
// Callers use it on directories to avoid descending.
func (r *Rule) Excluded(path, name string) bool {
	for _, g := range r.excludePath {
		if g.Match(path) {
			return true
		}
	}
	for _, g := range r.excludeName {
		if g.Match(name) {
			return true
		}
	}
	return false
}

// InScope reports whether the path lies at or beneath one of the rule's
// anchors, and the depth relative to that anchor. This is the walk-time
// equivalent of naming the path on find's command line.
func (r *Rule) InScope(path string) (depth int, ok bool) {
	for _, a := range r.anchors {
		if a.glob.Match(path) {
			return 0, true
		}
		// Try every ancestor: an anchor of /var/log puts /var/log/x/y in scope
		// at depth 2, and a globbed anchor works the same way.
		for i := 0; i < len(path); i++ {
			if path[i] != '/' || i == 0 {
				continue
			}
			if a.glob.Match(path[:i]) {
				return strings.Count(path[i:], "/"), true
			}
		}
		if a.glob.Match("/") {
			return strings.Count(path, "/"), true
		}
	}
	return 0, false
}

// Match answers the question find would have answered for this file.
func (r *Rule) Match(f *fsref.FileRef, env *Env) bool {
	if r.FromList {
		// Nothing is matched while walking; the paths arrive from a list.
		return false
	}
	depth, ok := r.InScope(f.Path)
	if !ok {
		return false
	}
	if r.hasMaxDepth && depth > r.maxDepth {
		return false
	}
	if r.Excluded(f.Path, f.Name) {
		return false
	}
	if len(r.types) > 0 && !r.types[f.TypeChar()] {
		return false
	}
	if len(r.pathPatterns) > 0 && !matchAny(r.pathPatterns, f.Path) {
		return false
	}
	if len(r.namePatterns) > 0 && !matchAny(r.namePatterns, f.Name) {
		return false
	}
	// find -size -Nc and +Nc are strict comparisons.
	if r.hasMaxSize && f.Size >= r.maxSize {
		return false
	}
	if r.hasMinSize && f.Size <= r.minSize {
		return false
	}
	if len(r.perms) > 0 && !matchAnyPerm(r.perms, f.Perm()) {
		return false
	}
	// no_user / no_group are only answerable against the image's own account
	// database. Without one, the honest answer is "cannot tell" -- reporting
	// every file as orphaned would be a wall of false positives, and find(1)
	// would have consulted the examiner's passwd file and reported nothing.
	if r.noUser {
		if env.UIDs == nil || env.UIDs[f.UID] {
			return false
		}
	}
	if r.noGroup {
		if env.GIDs == nil || env.GIDs[f.GID] {
			return false
		}
	}
	if !r.ignoreDateRange && !inDateRange(f, env) {
		return false
	}
	return true
}

func matchAny(gs []Glob, s string) bool {
	for _, g := range gs {
		if g.Match(s) {
			return true
		}
	}
	return false
}

func matchAnyPerm(ts []permTest, perm uint16) bool {
	for _, t := range ts {
		if t.match(perm) {
			return true
		}
	}
	return false
}

// inDateRange mirrors find's -mtime/-ctime/-atime handling: -N means "within
// the last N days", +N means "older than N days", and the three are OR'ed.
func inDateRange(f *fsref.FileRef, env *Env) bool {
	if env.StartDateDays == 0 && env.EndDateDays == 0 {
		return true
	}
	// find does not compare elapsed time directly: it divides the age by 24
	// hours and truncates, then compares whole days. So -mtime -N matches when
	// that count is < N, and +N when it is > N -- meaning +N only starts
	// matching at N+1 days, a day later than a naive comparison would.
	days := func(t time.Time) int64 {
		age := env.Now.Sub(t)
		if age < 0 {
			return 0 // a timestamp in the future counts as zero days old
		}
		return int64(age / (24 * time.Hour))
	}
	test := func(t time.Time) bool {
		d := days(t)
		if env.StartDateDays > 0 && d >= int64(env.StartDateDays) {
			return false
		}
		if env.EndDateDays > 0 && d <= int64(env.EndDateDays) {
			return false
		}
		return true
	}
	// find ORs whichever timestamps are enabled. Enabling none would exclude
	// everything, which is never what an operator means, so an empty selection
	// falls back to UAC's default pair.
	if !env.EnableMtime && !env.EnableAtime && !env.EnableCtime {
		return test(f.Mtime) || test(f.Ctime)
	}
	return (env.EnableMtime && test(f.Mtime)) ||
		(env.EnableCtime && test(f.Ctime)) ||
		(env.EnableAtime && test(f.Atime))
}

// Compile turns one artifact entry into a rule. It returns nil for entries that
// cannot run offline (the command collector) or that need a phase this walk
// does not provide (is_file_list, whose paths come from other files' contents).
func Compile(e artifact.Entry, doc *artifact.Doc, env *Env) (*Rule, error) {
	if !targetos.Supports(e.SupportedOS, env.OS) {
		return nil, nil
	}
	if e.Collector == "command" {
		return compileList(e, doc, env)
	}
	if !IsOffline(e.Collector) {
		return nil, nil
	}

	r := &Rule{
		ID:              e.ID(),
		Source:          e.Source,
		Kind:            Kind(e.Collector),
		OutputDir:       doc.OutputDirectory,
		OutputFile:      e.OutputFile,
		ignoreDateRange: e.IgnoreDateRange,
		noUser:          e.NoUser,
		noGroup:         e.NoGroup,
		Command:         e.Command,
	}
	if e.OutputDirectory != "" {
		r.OutputDir = e.OutputDirectory
	}

	if e.IsFileList {
		// The consumer half of a two-phase artifact: its paths come from a
		// list built while walking, so it matches nothing directly.
		if len(e.Path) == 0 {
			return nil, fmt.Errorf("%s: is_file_list with no path", e.ID())
		}
		r.FromList = true
		r.ListKey = normalizeListKey(expandSimple(e.Path[0], env))
		r.Homes = env.UserHomes
		return r, nil
	}

	// exclude_nologin_users narrows %user_home% to accounts that can actually
	// log in, which is what keeps a default collection from trawling every
	// service account's home directory.
	homes := env.UserHomes
	if e.ExcludeNologinUsers {
		homes = env.ShellUserHomes
	}

	needsUserHome := false
	for _, p := range e.Path {
		if strings.Contains(p, "%user_home%") {
			needsUserHome = true
		}
		for _, expanded := range expandVarsWithHomes(p, env, homes) {
			r.anchors = append(r.anchors, anchor{
				glob:  CompileGlob(expanded),
				depth: strings.Count(expanded, "/"),
			})
		}
	}
	if len(r.anchors) == 0 {
		// An artifact anchored at %user_home% against an image with no passwd
		// file has nothing to search. UAC reaches the same conclusion by
		// iterating over an empty user list and never running find, so this is
		// a skip, not a failure.
		if needsUserHome {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: no usable path", e.ID())
	}

	r.pathPatterns = compileGlobs(e.PathPattern)
	r.namePatterns = compileGlobs(e.NamePattern)
	r.excludeName = compileGlobs(append(append([]string(nil), e.ExcludeNamePattern...),
		env.ExcludeNamePattern...))

	// exclude_file_system names filesystem types; the walk needs paths. Resolve
	// them through the mount table and fold them into the path exclusions, so
	// there is one mechanism rather than two.
	excludePaths := append([]string(nil), e.ExcludePathPattern...)
	for _, p := range env.Mounts.PointsForTypes(e.ExcludeFileSystem) {
		excludePaths = append(excludePaths, p, p+"/*")
	}
	r.excludePath = compileGlobs(excludePaths)

	if len(e.FileType) > 0 {
		r.types = map[byte]bool{}
		for _, t := range e.FileType {
			if t == "" {
				continue
			}
			r.types[t[0]] = true
		}
	}
	for _, p := range e.Permissions {
		t, err := parsePerm(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.ID(), err)
		}
		r.perms = append(r.perms, t)
	}
	r.minSize, r.hasMinSize = e.MinFileSize, e.HasMinFileSize
	r.maxSize, r.hasMaxSize = e.MaxFileSize, e.HasMaxFileSize
	r.maxDepth, r.hasMaxDepth = e.MaxDepth, e.HasMaxDepth
	// A configured max_depth caps every rule; the tighter of the two wins.
	if env.MaxDepth > 0 && (!r.hasMaxDepth || env.MaxDepth < r.maxDepth) {
		r.maxDepth, r.hasMaxDepth = env.MaxDepth, true
	}
	return r, nil
}

// compileList turns a recognised HISTFILE-extraction command into a rule. An
// unrecognised command compiles to nothing: it is a live-system artifact this
// tool does not implement, and pretending otherwise would be worse than
// skipping it.
func compileList(e artifact.Entry, doc *artifact.Doc, env *Env) (*Rule, error) {
	spec, ok := ParseHistfileCommand(e.Command)
	if !ok {
		return nil, nil
	}
	if e.OutputFile == "" {
		return nil, nil
	}
	dir := doc.OutputDirectory
	if e.OutputDirectory != "" {
		dir = e.OutputDirectory
	}

	r := &Rule{
		ID:              e.ID(),
		Source:          e.Source,
		Kind:            KindList,
		Histfile:        spec,
		ListKey:         normalizeListKey(expandSimple(dir, env) + "/" + e.OutputFile),
		Homes:           env.UserHomes,
		ignoreDateRange: true,
	}
	for _, p := range spec.Files {
		for _, expanded := range expandVars(p, env) {
			r.anchors = append(r.anchors, anchor{
				glob:  CompileGlob(expanded),
				depth: strings.Count(expanded, "/"),
			})
		}
	}
	if len(r.anchors) == 0 {
		return nil, nil
	}
	// Only the named rc files, never anything beneath them.
	r.hasMaxDepth, r.maxDepth = true, 0
	return r, nil
}

// normalizeListKey reduces the many ways the same list is named -- with or
// without a leading slash, with the temp directory expanded or not -- to the
// basename, which is unique across the corpus and is what actually ties a
// producer to its consumer.
func normalizeListKey(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	return p
}

func compileGlobs(pats []string) []Glob {
	if len(pats) == 0 {
		return nil
	}
	out := make([]Glob, 0, len(pats))
	for _, p := range pats {
		out = append(out, CompileGlob(p))
	}
	return out
}

// expandVars resolves the %placeholders% UAC supports in paths. %user_home%
// fans one entry out into one anchor per home directory found in the image's
// passwd file.
func expandVars(p string, env *Env) []string {
	return expandVarsWithHomes(p, env, env.UserHomes)
}

func expandVarsWithHomes(p string, env *Env, homes []string) []string {
	if !strings.Contains(p, "%") {
		return []string{p}
	}
	if strings.Contains(p, "%user_home%") {
		out := make([]string, 0, len(homes))
		for _, h := range homes {
			out = append(out, expandSimple(strings.ReplaceAll(p, "%user_home%", h), env))
		}
		return out
	}
	return []string{expandSimple(p, env)}
}

func expandSimple(p string, env *Env) string {
	p = strings.ReplaceAll(p, "%temp_directory%", strings.TrimPrefix(env.TempDir, "/"))
	p = strings.ReplaceAll(p, "%artifacts_output_directory%", strings.TrimPrefix(env.OutputDir, "/"))
	p = strings.ReplaceAll(p, "%mount_point%", env.MountPoint)
	return p
}

// Set is a compiled collection of rules with a cheap first-pass filter.
type Set struct {
	Rules []*Rule
	// anyAnchored is true when at least one rule can match anywhere, which is
	// the case whenever bodyfile or hash_executables is enabled. It tells the
	// walker not to bother trying to skip subtrees.
	anyAnchored bool
	prefixes    []string
}

func NewSet(rs []*Rule) *Set {
	s := &Set{Rules: rs}
	for _, r := range rs {
		for _, p := range r.LiteralPrefixes() {
			if p == "/" {
				s.anyAnchored = true
			}
			s.prefixes = append(s.prefixes, p)
		}
	}
	return s
}

// MayContainMatches reports whether any rule could match something at or below
// dir. A false answer lets the walker skip the whole subtree.
func (s *Set) MayContainMatches(dir string) bool {
	if s.anyAnchored {
		return true
	}
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	for _, p := range s.prefixes {
		// Either the prefix reaches into this directory, or this directory is
		// on the way to the prefix.
		if strings.HasPrefix(p, dir) || strings.HasPrefix(dir, p) {
			return true
		}
	}
	return false
}

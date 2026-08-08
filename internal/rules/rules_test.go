package rules

import (
	"path/filepath"
	"testing"
	"time"

	"uacscan/internal/artifact"
	"uacscan/internal/fsref"
	"uacscan/internal/uacpath"
)

func TestGlobSpansSlashLikeFind(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		// The case Go's filepath.Match gets wrong for find's purposes.
		{"*/.git/hooks/*", "/home/u/proj/.git/hooks/pre-commit", true},
		{"*/Local Storage/leveldb/*", "/home/u/.config/x/Local Storage/leveldb/1.log", true},
		{"*/logs/*", "/opt/app/logs/a/b.log", true},
		{"*/logs/*", "/opt/app/log/b.log", false},
		{"authorized_keys*", "authorized_keys2", true},
		{"authorized_keys*", "authorized_key", false},
		{"*.log", "x.log", true},
		{"?.log", "x.log", true},
		{"?.log", "xy.log", false},
		{"[abc].log", "b.log", true},
		{"[!abc].log", "b.log", false},
		{"[!abc].log", "d.log", true},
		{"[a-c].log", "c.log", true},
		{"*", "anything/at/all", true},
		{"/etc", "/etc", true},
		{"/etc", "/etcx", false},
	}
	for _, tc := range cases {
		g := CompileGlob(tc.pat)
		if got := g.Match(tc.s); got != tc.want {
			t.Errorf("Glob(%q).Match(%q) = %v, want %v", tc.pat, tc.s, got, tc.want)
		}
	}
}

func TestGlobAgreesWithFilepathMatchWhenNoSlashSpanning(t *testing.T) {
	// Where the two are supposed to agree, they must.
	pats := []string{"*.log", "a?c", "[a-z]*", "exact"}
	subjects := []string{"a.log", "abc", "zebra", "exact", "no"}
	for _, p := range pats {
		for _, s := range subjects {
			want, err := filepath.Match(p, s)
			if err != nil {
				t.Fatal(err)
			}
			if got := CompileGlob(p).Match(s); got != want {
				t.Errorf("pattern %q subject %q: got %v, filepath.Match %v", p, s, got, want)
			}
		}
	}
}

func TestInScopeAndDepth(t *testing.T) {
	r := &Rule{anchors: []anchor{{glob: CompileGlob("/var/log")}}}
	cases := []struct {
		path  string
		depth int
		ok    bool
	}{
		{"/var/log", 0, true},
		{"/var/log/syslog", 1, true},
		{"/var/log/a/b/c", 3, true},
		{"/var/logging", 0, false},
		{"/var", 0, false},
		{"/etc/passwd", 0, false},
	}
	for _, tc := range cases {
		d, ok := r.InScope(tc.path)
		if ok != tc.ok || (ok && d != tc.depth) {
			t.Errorf("InScope(%q) = (%d,%v), want (%d,%v)", tc.path, d, ok, tc.depth, tc.ok)
		}
	}
}

func TestInScopeRootAnchorCoversEverything(t *testing.T) {
	r := &Rule{anchors: []anchor{{glob: CompileGlob("/")}}}
	for _, p := range []string{"/", "/etc", "/etc/passwd", "/a/b/c/d"} {
		if _, ok := r.InScope(p); !ok {
			t.Errorf("root anchor did not cover %q", p)
		}
	}
}

func TestPermMatching(t *testing.T) {
	// -perm -4000 means "setuid bit set", regardless of the other bits.
	suid, err := parsePerm("-4000")
	if err != nil {
		t.Fatal(err)
	}
	if !suid.match(04755) {
		t.Error("-4000 should match 04755")
	}
	if suid.match(00755) {
		t.Error("-4000 should not match 00755")
	}
	// -perm -0004 means world-readable.
	wr, _ := parsePerm("-0004")
	if !wr.match(00644) || wr.match(00640) {
		t.Error("-0004 world-readable test wrong")
	}
	// Exact form.
	exact, _ := parsePerm("0644")
	if !exact.match(00644) || exact.match(00645) {
		t.Error("exact perm test wrong")
	}
	if _, err := parsePerm("/4000"); err == nil {
		t.Error("expected an error for the unsupported /MODE form")
	}
}

func TestSizeComparisonsAreStrictLikeFind(t *testing.T) {
	r := &Rule{
		anchors:    []anchor{{glob: CompileGlob("/")}},
		maxSize:    100,
		hasMaxSize: true,
	}
	env := &Env{Now: time.Now()}
	mk := func(size int64) *fsref.FileRef {
		return &fsref.FileRef{Path: "/f", Name: "f", Size: size, RawMode: 0100644}
	}
	if !r.Match(mk(99), env) {
		t.Error("99 should match -size -100c")
	}
	if r.Match(mk(100), env) {
		t.Error("100 must not match -size -100c (find is strict)")
	}
	if r.Match(mk(101), env) {
		t.Error("101 must not match -size -100c")
	}
}

func TestNoUserUsesImageAccountDatabase(t *testing.T) {
	r := &Rule{anchors: []anchor{{glob: CompileGlob("/")}}, noUser: true}
	// UID 1000 exists in the image; 4242 does not.
	env := &Env{Now: time.Now(), UIDs: map[uint32]bool{0: true, 1000: true}}
	known := &fsref.FileRef{Path: "/a", Name: "a", UID: 1000, RawMode: 0100644}
	orphan := &fsref.FileRef{Path: "/b", Name: "b", UID: 4242, RawMode: 0100644}
	if r.Match(known, env) {
		t.Error("no_user matched a file whose owner exists in the image passwd")
	}
	if !r.Match(orphan, env) {
		t.Error("no_user failed to match an orphaned file")
	}
}

// Without the image's account database a no_user rule cannot be evaluated, and
// must report nothing rather than flagging every file.
func TestNoUserReportsNothingWithoutAnAccountDatabase(t *testing.T) {
	r := &Rule{anchors: []anchor{{glob: CompileGlob("/")}}, noUser: true}
	env := &Env{Now: time.Now()} // no UIDs loaded
	f := &fsref.FileRef{Path: "/a", Name: "a", UID: 4242, RawMode: 0100644}
	if r.Match(f, env) {
		t.Error("no_user matched with no account database; every file would be a false positive")
	}
}

func TestDateRangeOrsTheThreeTimestamps(t *testing.T) {
	now := time.Now()
	env := &Env{Now: now, StartDateDays: 7}
	r := &Rule{anchors: []anchor{{glob: CompileGlob("/")}}}

	old := now.Add(-30 * 24 * time.Hour)
	recent := now.Add(-1 * 24 * time.Hour)

	allOld := &fsref.FileRef{Path: "/a", Name: "a", RawMode: 0100644, Mtime: old, Ctime: old, Atime: old}
	if r.Match(allOld, env) {
		t.Error("file older than the range should not match")
	}
	// Only ctime is recent -- find ORs the three, so it is still in range.
	ctimeRecent := &fsref.FileRef{Path: "/a", Name: "a", RawMode: 0100644, Mtime: old, Ctime: recent, Atime: old}
	if !r.Match(ctimeRecent, env) {
		t.Error("recent ctime should bring the file into range")
	}
	// ignore_date_range overrides everything.
	r.ignoreDateRange = true
	if !r.Match(allOld, env) {
		t.Error("ignore_date_range should defeat the date filter")
	}
}

func TestExcludePatternsPrune(t *testing.T) {
	r := &Rule{
		anchors:     []anchor{{glob: CompileGlob("/")}},
		excludePath: compileGlobs([]string{"/proc", "/sys"}),
		excludeName: compileGlobs([]string{"*.tmp"}),
	}
	if !r.Excluded("/proc", "proc") {
		t.Error("/proc should be excluded")
	}
	if !r.Excluded("/var/x.tmp", "x.tmp") {
		t.Error("*.tmp should be excluded by name")
	}
	if r.Excluded("/etc/passwd", "passwd") {
		t.Error("/etc/passwd should not be excluded")
	}
}

func TestCompileUserHomeFansOut(t *testing.T) {
	e := artifact.Entry{
		Source:    "files/ssh/authorized_keys.yaml",
		Collector: "file",
		Path:      []string{"%user_home%/.ssh/authorized_keys*"},
	}
	env := &Env{UserHomes: []string{"/root", "/home/alice", "/home/bob"}, Now: time.Now()}
	r, err := Compile(e, &artifact.Doc{OutputDirectory: "/ssh"}, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.anchors) != 3 {
		t.Fatalf("got %d anchors, want 3", len(r.anchors))
	}
	f := &fsref.FileRef{Path: "/home/alice/.ssh/authorized_keys", Name: "authorized_keys", RawMode: 0100600}
	if !r.Match(f, env) {
		t.Error("alice's authorized_keys should match")
	}
	f2 := &fsref.FileRef{Path: "/home/carol/.ssh/authorized_keys", Name: "authorized_keys", RawMode: 0100600}
	if r.Match(f2, env) {
		t.Error("carol has no home in the image; should not match")
	}
}

func TestCompileSkipsNonOfflineAndTwoPhase(t *testing.T) {
	env := &Env{Now: time.Now()}
	doc := &artifact.Doc{}
	cmd := artifact.Entry{Collector: "command", Command: "ps aux"}
	if r, err := Compile(cmd, doc, env); err != nil || r != nil {
		t.Errorf("command collector should compile to nil, got %v %v", r, err)
	}
	fl := artifact.Entry{Collector: "file", IsFileList: true, Path: []string{"/x"}}
	if r, err := Compile(fl, doc, env); err != nil || r != nil {
		t.Errorf("is_file_list should compile to nil, got %v %v", r, err)
	}
}

func TestSetSkipsUnreachableSubtrees(t *testing.T) {
	env := &Env{Now: time.Now()}
	doc := &artifact.Doc{}
	e := artifact.Entry{Collector: "file", Path: []string{"/var/log"}}
	r, err := Compile(e, doc, env)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSet([]*Rule{r})
	if !s.MayContainMatches("/var") {
		t.Error("/var is on the way to /var/log; must be descended")
	}
	if !s.MayContainMatches("/var/log/nginx") {
		t.Error("/var/log/nginx is under the anchor")
	}
	if s.MayContainMatches("/home/alice") {
		t.Error("/home/alice cannot contain a match and should be skipped")
	}

	// Once anything is anchored at /, nothing can be skipped.
	body := artifact.Entry{Collector: "stat", Path: []string{"/"}}
	br, _ := Compile(body, doc, env)
	s2 := NewSet([]*Rule{r, br})
	if !s2.MayContainMatches("/home/alice") {
		t.Error("a root-anchored rule must defeat subtree skipping")
	}
}

// The compiler has to survive the real corpus.
func TestCompileEveryOfflineArtifact(t *testing.T) {
	root := uacArtifactRoot(t)
	docs, errs := artifact.LoadDir(root)
	if len(errs) > 0 {
		t.Fatalf("corpus failed to parse: %v", errs)
	}
	env := &Env{
		Now:       time.Now(),
		UserHomes: []string{"/root", "/home/alice"},
		TempDir:   "/uac-data.tmp",
		OutputDir: "/out",
	}
	byKind := map[Kind]int{}
	var compiled []*Rule
	for _, d := range docs {
		for _, e := range d.Artifacts {
			r, err := Compile(e, d, env)
			if err != nil {
				t.Errorf("%s: %v", e.ID(), err)
				continue
			}
			if r == nil {
				continue
			}
			compiled = append(compiled, r)
			byKind[r.Kind]++
		}
	}
	t.Logf("compiled %d offline rules: %v", len(compiled), byKind)
	if byKind[KindStat] == 0 || byKind[KindHash] == 0 || byKind[KindFind] == 0 || byKind[KindFile] == 0 {
		t.Errorf("expected all four offline kinds, got %v", byKind)
	}

	// Every compiled rule must survive being asked about an ordinary path
	// without panicking, and the root-anchored ones must accept it.
	f := &fsref.FileRef{Path: "/etc/passwd", Name: "passwd", RawMode: 0100644, Size: 100}
	rooted := 0
	for _, r := range compiled {
		if r.Match(f, env) {
			rooted++
		}
	}
	if rooted == 0 {
		t.Error("no rule matched /etc/passwd; the bodyfile rule alone should have")
	}
	t.Logf("%d rules match /etc/passwd", rooted)
}

func uacArtifactRoot(t *testing.T) string {
	t.Helper()
	d := uacpath.Artifacts()
	if d == "" {
		t.Skip("UAC artifact corpus not found; set UAC_ROOT")
	}
	return d
}

// UAC ships enable_find_atime: false, so a file whose only recent timestamp is
// its access time must stay out of the date range.
func TestAtimeIsExcludedFromTheDateRangeByDefault(t *testing.T) {
	now := time.Now()
	old := now.Add(-30 * 24 * time.Hour)
	recent := now.Add(-1 * 24 * time.Hour)
	r := &Rule{anchors: []anchor{{glob: CompileGlob("/")}}}
	f := &fsref.FileRef{Path: "/a", Name: "a", RawMode: 0100644, Mtime: old, Ctime: old, Atime: recent}

	uacDefaults := &Env{Now: now, StartDateDays: 7, EnableMtime: true, EnableCtime: true, EnableAtime: false}
	if r.Match(f, uacDefaults) {
		t.Error("a recent atime brought the file into range; UAC disables atime")
	}
	withAtime := &Env{Now: now, StartDateDays: 7, EnableMtime: true, EnableCtime: true, EnableAtime: true}
	if !r.Match(f, withAtime) {
		t.Error("with atime enabled the file should be in range")
	}
}

// An image with no passwd file leaves %user_home% with nothing to expand to.
// That is a skip, not an error: UAC iterates an empty user list and never runs
// find at all.
func TestUserHomeArtifactSkippedWhenImageHasNoAccounts(t *testing.T) {
	e := artifact.Entry{
		Source:    "files/shell/bash.yaml",
		Collector: "file",
		Path:      []string{"%user_home%/.bash_history"},
	}
	env := &Env{Now: time.Now()} // no UserHomes
	r, err := Compile(e, &artifact.Doc{}, env)
	if err != nil {
		t.Fatalf("expected a silent skip, got %v", err)
	}
	if r != nil {
		t.Error("expected no rule when there are no home directories")
	}

	// A path with no placeholder and no anchors is still a real problem.
	bad := artifact.Entry{Source: "x.yaml", Collector: "file", Path: nil}
	if _, err := Compile(bad, &artifact.Doc{}, env); err == nil {
		t.Error("an entry with no path at all should still be an error")
	}
}

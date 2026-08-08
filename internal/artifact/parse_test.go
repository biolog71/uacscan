package artifact

import (
	"reflect"
	"strings"
	"testing"

	"uacscan/internal/uacpath"
)

func TestParseBodyfile(t *testing.T) {
	src := `version: 4.0
output_directory: /bodyfile
artifacts:
  -
    description: Collect file stat information to create a bodyfile.
    supported_os: [all]
    collector: stat
    path: /
    exclude_file_system: [proc, procfs]
    output_file: bodyfile.txt
`
	doc, err := Parse(strings.NewReader(src), "bodyfile/bodyfile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if doc.OutputDirectory != "/bodyfile" {
		t.Errorf("OutputDirectory = %q", doc.OutputDirectory)
	}
	if len(doc.Artifacts) != 1 {
		t.Fatalf("got %d artifacts, want 1", len(doc.Artifacts))
	}
	a := doc.Artifacts[0]
	if a.Collector != "stat" {
		t.Errorf("Collector = %q", a.Collector)
	}
	if !reflect.DeepEqual(a.Path, []string{"/"}) {
		t.Errorf("Path = %#v", a.Path)
	}
	if !reflect.DeepEqual(a.ExcludeFileSystem, []string{"proc", "procfs"}) {
		t.Errorf("ExcludeFileSystem = %#v", a.ExcludeFileSystem)
	}
	if a.ID() != "bodyfile/bodyfile#0" {
		t.Errorf("ID = %q", a.ID())
	}
}

// The dialect features that defeat a real YAML parser.
func TestParseAcceptsNonYAMLDialect(t *testing.T) {
	src := "version: 2.0\n" +
		"artifacts:\n" +
		"  -\n" +
		"    description: has\ta tab\n" +
		"    collector: file\n" +
		"    path: %user_home%/.ssh/authorized_keys*\n" +
		"    max_file_size: 3221225472\n" +
		"  -\n" +
		"    description: 'quoted'-ish description\n" +
		"    collector: command\n" +
		"    command: stat --format='{\"File\": \"%n\", \"Size\": %s}' /tmp\n"

	doc, err := Parse(strings.NewReader(src), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Artifacts) != 2 {
		t.Fatalf("got %d artifacts, want 2", len(doc.Artifacts))
	}
	a := doc.Artifacts[0]
	if !reflect.DeepEqual(a.Path, []string{"%user_home%/.ssh/authorized_keys*"}) {
		t.Errorf("bare %%var%% path = %#v", a.Path)
	}
	if a.Description != "has a tab" {
		t.Errorf("tab in description = %q", a.Description)
	}
	if a.MaxFileSize != 3221225472 || !a.HasMaxFileSize {
		t.Errorf("MaxFileSize = %d", a.MaxFileSize)
	}
	// A colon inside a command value must not be read as a key separator.
	b := doc.Artifacts[1]
	want := `stat --format='{"File": "%n", "Size": %s}' /tmp`
	if b.Command != want {
		t.Errorf("Command = %q, want %q", b.Command, want)
	}
}

func TestShellSplitKeepsQuotedPathSegments(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`/a /b`, []string{"/a", "/b"}},
		{`%user_home%/Library/"Application Support"/foo`, []string{"%user_home%/Library/Application Support/foo"}},
		{`  /only  `, []string{"/only"}},
		{`/a/b`, []string{"/a/b"}},
		{`%user_home%/.zsh_history %user_home%/.zsh_sessions`, []string{"%user_home%/.zsh_history", "%user_home%/.zsh_sessions"}},
	}
	for _, tc := range cases {
		if got := shellSplit(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("shellSplit(%q) = %#v, want %#v", tc.in, got, tc.want)
		}
	}
}

func TestInlineListItemKey(t *testing.T) {
	src := `artifacts:
  - description: inline
    collector: find
    path: /tmp
`
	doc, err := Parse(strings.NewReader(src), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Artifacts) != 1 || doc.Artifacts[0].Description != "inline" {
		t.Fatalf("got %#v", doc.Artifacts)
	}
	if doc.Artifacts[0].Collector != "find" {
		t.Errorf("Collector = %q", doc.Artifacts[0].Collector)
	}
}

// The parser has to survive the real corpus, not just synthetic input. This is
// the test that would have caught the %-scalar problem.
func TestParseEveryRealUACArtifact(t *testing.T) {
	root := uacArtifactRoot(t)
	docs, errs := LoadDir(root)
	if len(errs) > 0 {
		for f, err := range errs {
			t.Errorf("%s: %v", f, err)
		}
	}
	if len(docs) < 100 {
		t.Fatalf("only parsed %d documents; expected the full corpus", len(docs))
	}

	collectors := map[string]int{}
	entries := 0
	for _, d := range docs {
		for _, a := range d.Artifacts {
			entries++
			if a.Collector == "" {
				t.Errorf("%s entry %d has no collector", d.Source, a.Index)
			}
			collectors[a.Collector]++
			if a.Collector != "command" && len(a.Path) == 0 {
				t.Errorf("%s entry %d: %s collector with no path", d.Source, a.Index, a.Collector)
			}
		}
	}
	t.Logf("parsed %d documents, %d entries, collectors=%v", len(docs), entries, collectors)

	// Counts established by independent analysis of the corpus. If UAC adds
	// artifacts these move, but a sudden collapse means the parser broke.
	if collectors["file"] < 400 {
		t.Errorf("file collector entries = %d, expected >400", collectors["file"])
	}
	if collectors["command"] < 600 {
		t.Errorf("command collector entries = %d, expected >600", collectors["command"])
	}
}

func uacArtifactRoot(t *testing.T) string {
	t.Helper()
	d := uacpath.Artifacts()
	if d == "" {
		t.Skip("UAC artifact corpus not found; set UAC_ROOT")
	}
	return d
}

func TestStripCommentHonoursQuotes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1073741824 # 1GB", "1073741824"},
		{"10485760 # 10MB", "10485760"},
		{"/var/log", "/var/log"},
		{"grep '#' /etc/passwd", "grep '#' /etc/passwd"},
		{`awk "#" x # trailing`, `awk "#" x`},
		{"#leading", ""},
		{"a#b", "a#b"}, // no space before '#': not a comment
	}
	for _, tc := range cases {
		if got := stripComment(tc.in); got != tc.want {
			t.Errorf("stripComment(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

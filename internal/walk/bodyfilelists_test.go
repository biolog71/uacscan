package walk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"uacscan/collector"
	"uacscan/internal/artifact"
	"uacscan/internal/config"
	"uacscan/internal/content"
	"uacscan/internal/fsref"
	"uacscan/internal/passwd"
	"uacscan/internal/rules"
	"uacscan/internal/spool"
	"uacscan/internal/targetos"
	"uacscan/test/fixture"
)

// setupSourced is setup, except it compiles multiple artifact documents with
// their real source paths rather than a single "test.yaml" -- required here
// because rules.ApplyBodyfileListsShadowing keys its decisions off
// artifact.Entry.Source, exactly as the real artifact corpus does (e.g.
// "bodyfile/bodyfile.yaml"), and setup's single-doc form cannot express that.
func setupSourced(t *testing.T, docs map[string]string) *harness {
	t.Helper()
	root := t.TempDir()
	if err := fixture.Build(root); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()

	accounts := passwd.Load(root)
	conf := config.Default()
	env := &rules.Env{
		MountPoint:    root,
		Now:           time.Now(),
		OS:            targetos.Host(),
		EnableMtime:   conf.EnableFindMtime,
		EnableAtime:   conf.EnableFindAtime,
		EnableCtime:   conf.EnableFindCtime,
		HashAlgorithm: conf.HashAlgorithm,
		UserHomes:     accounts.Homes,
		UIDs:          accounts.UIDs,
		GIDs:          accounts.GIDs,
	}

	var compiled []*rules.Rule
	for source, yaml := range docs {
		doc, err := artifact.Parse(strings.NewReader(yaml), source)
		if err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		for _, e := range doc.Artifacts {
			r, err := rules.Compile(e, doc, env)
			if err != nil {
				t.Fatalf("%s: %v", source, err)
			}
			if r != nil {
				compiled = append(compiled, r)
			}
		}
	}
	compiled = rules.ApplyBodyfileListsShadowing(compiled)
	if len(compiled) == 0 {
		t.Fatal("no rules compiled from the test artifacts")
	}

	store, err := spool.NewStore(out)
	if err != nil {
		t.Fatal(err)
	}
	cache := fsref.NewCache(root)
	broker := content.NewBroker()
	ctx := &collector.Context{Cache: cache, Broker: broker, Store: store, Env: env, OutputRoot: out}
	broker.OnError = func(p, c string, err error) { ctx.RecordError(p, c, err) }

	var cs []collector.Collector
	for _, r := range compiled {
		c, err := collector.New(r, ctx)
		if err != nil {
			t.Fatal(err)
		}
		cs = append(cs, c)
	}
	return &harness{
		root:  root,
		out:   out,
		store: store,
		ctx:   ctx,
		env:   env,
		w: &Walker{
			Root: root, Cache: cache, Broker: broker,
			Set: rules.NewSet(compiled), Collectors: cs,
			Recorded: ctx.RecordedErrors,
		},
	}
}

const bodyfileYAML = `version: 1.0
output_directory: /bodyfile
artifacts:
  -
    collector: stat
    path: /
    output_file: bodyfile.txt
`

const bodyfileListsYAML = `version: 1.0
output_directory: /system
artifacts:
  -
    collector: command
    command: bodyfile2filelists.sh "/%artifacts_output_directory%/bodyfile/bodyfile.txt" "%mount_point%"
`

// The real artifact text for the two permission-bit artifacts UAC's own
// corpus gets wrong (see rules.KindBodyfileLists) -- used to prove the
// shadow suppression actually prevents them from re-polluting the output.
const worldWritableFilesYAML = `version: 1.0
output_directory: /system
artifacts:
  -
    collector: find
    path: /
    file_type: [f]
    permissions: [-0004]
    output_file: world_writable_files.txt
`

func TestBodyfileListsClassifiesEveryCategory(t *testing.T) {
	h := setupSourced(t, map[string]string{
		"bodyfile/bodyfile.yaml":         bodyfileYAML,
		"system/bodyfile2filelists.yaml": bodyfileListsYAML,
	})
	h.run(t)

	cases := []struct {
		file string
		want []string
		miss []string // paths that must NOT appear
	}{
		{"system/suid.txt", []string{"/usr/bin/suid_binary"}, []string{"/usr/bin/sgid_binary", "/usr/bin/normal"}},
		{"system/sgid.txt", []string{"/usr/bin/sgid_binary"}, []string{"/usr/bin/suid_binary"}},
		{"system/hidden_files.txt", []string{"/.hidden_root_file"}, []string{"/usr/bin/normal"}},
		{"system/hidden_directories.txt", []string{"/home/alice/.hidden_dir"}, nil},
		{"system/world_writable_files.txt", []string{"/tmp/world_writable"}, []string{"/var/tmp/group_writable"}},
		{"system/world_writable_directories.txt", []string{"/tmp", "/var/spool/incoming"}, nil},
		// The one distinction that only bodyfile2filelists.sh's own logic
		// makes: sticky world-writable directories are excluded here even
		// though they are included above.
		{"system/world_writable_not_sticky_directories.txt", []string{"/var/spool/incoming"}, []string{"/tmp"}},
		// /tmp/world_writable is mode 0666 (rw-rw-rw-), which genuinely has the
		// group-write bit set too, so it correctly belongs in both files; only
		// /usr/bin/normal (0755, no write bits for anyone but the owner) is a
		// safe "must not appear" check here.
		{"system/group_writable_files.txt", []string{"/var/tmp/group_writable"}, []string{"/usr/bin/normal"}},
	}
	for _, tc := range cases {
		lines := h.lines(t, tc.file)
		for _, want := range tc.want {
			if !contains(lines, want) {
				t.Errorf("%s: missing %q, got %v", tc.file, want, lines)
			}
		}
		for _, miss := range tc.miss {
			if contains(lines, miss) {
				t.Errorf("%s: wrongly contains %q", tc.file, miss)
			}
		}
	}
}

// A file owned by a UID the image's own passwd file does not list is
// unresolvable, not a directive to flag everything -- controlled here by
// overriding the account database rather than chown(2), which needs
// privileges the test runner may not have.
func TestBodyfileListsUnknownOwner(t *testing.T) {
	h := setupSourced(t, map[string]string{
		"bodyfile/bodyfile.yaml":         bodyfileYAML,
		"system/bodyfile2filelists.yaml": bodyfileListsYAML,
	})
	// Every file the test process creates is owned by the test process's own
	// uid/gid. Excluding exactly that uid/gid from the "known" set makes every
	// file in the fixture "unknown", which is deterministic and needs no
	// privilege to set up.
	h.env.UIDs = map[uint32]bool{}
	h.env.GIDs = map[uint32]bool{}
	h.run(t)

	uf := h.lines(t, "system/user_name_unknown_files.txt")
	if !contains(uf, "/usr/bin/normal") {
		t.Errorf("expected every file to be user_name_unknown, got %v", uf)
	}
	gf := h.lines(t, "system/group_name_unknown_files.txt")
	if !contains(gf, "/usr/bin/normal") {
		t.Errorf("expected every file to be group_name_unknown, got %v", gf)
	}

	// And the inverse: a nil map (no account database at all) must answer
	// "cannot tell" rather than flagging everything, matching the no_user/
	// no_group semantics used everywhere else -- deliberately not what
	// bodyfile2filelists.sh itself does with an empty passwd file.
	h2 := setupSourced(t, map[string]string{
		"bodyfile/bodyfile.yaml":         bodyfileYAML,
		"system/bodyfile2filelists.yaml": bodyfileListsYAML,
	})
	h2.env.UIDs = nil
	h2.env.GIDs = nil
	h2.run(t)
	if b, err := os.ReadFile(filepath.Join(h2.out, "system/user_name_unknown_files.txt")); err == nil && len(b) > 0 {
		t.Errorf("with no account database at all, nothing should be flagged unknown, got:\n%s", b)
	}
}

// This is the regression test for the actual bug found by running against a
// live root filesystem: the standalone world_writable_files.yaml declares
// permissions: [-0004] (world-READ), not [-0002] (world-WRITE). Included
// alongside bodyfile2filelists.yaml, it must be shadowed -- not merged with,
// not overriding -- bodyfile2filelists' correct classification.
func TestBodyfileListsShadowsTheBuggyStandaloneArtifact(t *testing.T) {
	h := setupSourced(t, map[string]string{
		"bodyfile/bodyfile.yaml":           bodyfileYAML,
		"system/bodyfile2filelists.yaml":   bodyfileListsYAML,
		"system/world_writable_files.yaml": worldWritableFilesYAML,
	})
	h.run(t)

	lines := h.lines(t, "system/world_writable_files.txt")
	if !contains(lines, "/tmp/world_writable") {
		t.Errorf("the genuinely world-writable fixture file is missing: %v", lines)
	}
	// /usr/bin/normal is mode 0755: world-readable, not world-writable. The
	// standalone artifact's -0004 would match it; bodyfile2filelists' -0002
	// equivalent (others_write_mode == "w") must not.
	if contains(lines, "/usr/bin/normal") {
		t.Errorf("a merely world-readable file leaked in -- the standalone -0004 "+
			"rule was not shadowed: %v", lines)
	}
}

// Without bodyfile/bodyfile.yaml also selected, the standalone artifact is
// the only thing that can produce this output at all -- exactly UAC's own
// fallback when its "if [ -s bodyfile.txt ]" condition is false. This is
// wrong per the artifact's own declared permission value, but reproducing
// that here is the correct behaviour: it is what UAC would also do in this
// situation, wrong permission bits and all.
func TestBodyfileListsWithoutBodyfileFallsBackToStandaloneArtifact(t *testing.T) {
	h := setupSourced(t, map[string]string{
		"system/bodyfile2filelists.yaml":   bodyfileListsYAML,
		"system/world_writable_files.yaml": worldWritableFilesYAML,
	})
	h.run(t)

	lines := h.lines(t, "system/world_writable_files.txt")
	if !contains(lines, "/usr/bin/normal") {
		t.Errorf("without a bodyfile, the standalone (permissive) rule should have run: %v", lines)
	}
}

func contains(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

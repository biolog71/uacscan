package rules

import (
	"testing"

	"uacscan/internal/artifact"
)

func TestCompileBodyfileListsRecognisesTheRealCommand(t *testing.T) {
	// The exact command string from artifacts/system/bodyfile2filelists.yaml.
	e := artifact.Entry{
		Source:    "system/bodyfile2filelists.yaml",
		Collector: "command",
		Command:   `bodyfile2filelists.sh "/%artifacts_output_directory%/bodyfile/bodyfile.txt" "%mount_point%"`,
	}
	doc := &artifact.Doc{OutputDirectory: "/system"}
	r := compileBodyfileLists(e, doc)
	if r == nil {
		t.Fatal("did not recognise the real bodyfile2filelists.sh command")
	}
	if r.Kind != KindBodyfileLists {
		t.Errorf("Kind = %q, want %q", r.Kind, KindBodyfileLists)
	}
	if r.OutputDir != "/system" {
		t.Errorf("OutputDir = %q, want /system", r.OutputDir)
	}
	if r.Source != "system/bodyfile2filelists.yaml" {
		t.Errorf("Source = %q", r.Source)
	}
	if len(r.anchors) != 1 {
		t.Fatalf("got %d anchors, want 1 (rooted at /)", len(r.anchors))
	}
}

func TestCompileBodyfileListsIgnoresOtherCommands(t *testing.T) {
	doc := &artifact.Doc{}
	for _, cmd := range []string{
		"ps aux",
		"getcap",
		`grep -E "HISTFILE=.*" %user_home%/.bashrc | sed -e 's|.*HISTFILE=||' -e 's|^~/|%user_home%/|'`,
		"",
		"echo bodyfile2filelists.sh", // must not match as a substring anywhere
	} {
		e := artifact.Entry{Collector: "command", Command: cmd}
		if r := compileBodyfileLists(e, doc); r != nil {
			t.Errorf("wrongly recognised %q", cmd)
		}
	}
}

func mkRule(source string, kind Kind) *Rule {
	return &Rule{Source: source, Kind: kind}
}

func TestApplyBodyfileListsShadowingDropsExactlyTheShadowedTwelve(t *testing.T) {
	rs := []*Rule{
		mkRule("bodyfile/bodyfile.yaml", KindStat),
		mkRule("system/bodyfile2filelists.yaml", KindBodyfileLists),
		mkRule("system/suid.yaml", KindFind),
		mkRule("system/sgid.yaml", KindFind),
		mkRule("system/hidden_files.yaml", KindFind),
		mkRule("system/hidden_directories.yaml", KindFind),
		mkRule("system/user_name_unknown_files.yaml", KindFind),
		mkRule("system/user_name_unknown_directories.yaml", KindFind),
		mkRule("system/group_name_unknown_files.yaml", KindFind),
		mkRule("system/group_name_unknown_directories.yaml", KindFind),
		mkRule("system/world_writable_files.yaml", KindFind),
		mkRule("system/world_writable_directories.yaml", KindFind),
		mkRule("system/group_writable_files.yaml", KindFind),
		mkRule("system/group_writable_directories.yaml", KindFind),
		// Not shadowed: gated on command_exists(...), a different mechanism.
		mkRule("system/getcap.yaml", KindFind),
		mkRule("system/immutable_files.yaml", KindFind),
		// Not shadowed: an unrelated artifact entirely.
		mkRule("files/ssh/authorized_keys.yaml", KindFile),
	}
	got := ApplyBodyfileListsShadowing(rs)

	keep := map[string]bool{
		"bodyfile/bodyfile.yaml":         true,
		"system/bodyfile2filelists.yaml": true,
		"system/getcap.yaml":             true,
		"system/immutable_files.yaml":    true,
		"files/ssh/authorized_keys.yaml": true,
	}
	if len(got) != len(keep) {
		t.Errorf("kept %d rules, want %d", len(got), len(keep))
	}
	for _, r := range got {
		if !keep[r.Source] {
			t.Errorf("%s should have been shadowed and dropped", r.Source)
		}
		delete(keep, r.Source)
	}
	for missing := range keep {
		t.Errorf("%s was dropped but should have been kept", missing)
	}
}

// If bodyfile/bodyfile.yaml was not also selected, UAC's own condition on
// bodyfile2filelists.yaml -- "if [ -s bodyfile.txt ]" -- would be false, so it
// is the KindBodyfileLists rule that gets dropped, and the standalone
// artifacts run normally instead. Dropping both would silently produce
// nothing for every one of these categories.
func TestApplyBodyfileListsShadowingWithoutBodyfileKeepsTheStandaloneArtifacts(t *testing.T) {
	rs := []*Rule{
		mkRule("system/bodyfile2filelists.yaml", KindBodyfileLists),
		mkRule("system/world_writable_files.yaml", KindFind),
		mkRule("system/suid.yaml", KindFind),
	}
	got := ApplyBodyfileListsShadowing(rs)
	if len(got) != 2 {
		t.Fatalf("got %d rules, want 2 (the two standalone artifacts)", len(got))
	}
	for _, r := range got {
		if r.Kind == KindBodyfileLists {
			t.Error("KindBodyfileLists rule should have been dropped without a bodyfile")
		}
	}
}

// Without bodyfile2filelists.yaml selected at all, nothing about the set
// should change -- this is the common case (most artifact selections do not
// include it) and must be a complete no-op.
func TestApplyBodyfileListsShadowingIsANoOpWithoutTheArtifact(t *testing.T) {
	rs := []*Rule{
		mkRule("system/world_writable_files.yaml", KindFind),
		mkRule("system/suid.yaml", KindFind),
		mkRule("bodyfile/bodyfile.yaml", KindStat),
	}
	got := ApplyBodyfileListsShadowing(rs)
	if len(got) != len(rs) {
		t.Errorf("got %d rules, want all %d unchanged", len(got), len(rs))
	}
}

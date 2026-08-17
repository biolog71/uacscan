package rules

import (
	"strings"

	"uacscan/internal/artifact"
)

// KindBodyfileLists is not a UAC collector name. It is the native
// reimplementation of bin/bodyfile2filelists.sh, UAC's own command collector
// that classifies every bodyfile entry into fourteen categories in a single
// pass -- sockets, hidden files/directories, suid/sgid, world/group-writable
// files/directories (plus a non-sticky-directory subset of world-writable),
// and files/directories owned by an unknown user or group.
//
// Reimplementing it natively rather than treating it as an ordinary
// out-of-scope command collector matters for a reason discovered by running a
// real acquisition against a live root filesystem and diffing it against this
// exact artifact: bodyfile2filelists.yaml always runs before the standalone
// per-category YAML artifacts in every UAC profile that includes both, and
// each of those standalone artifacts is condition-gated to skip once
// bodyfile2filelists.sh has already written their output file --
//
//	condition: if [ ! -f ".../world_writable_files.txt" ]; then true; else false; fi
//
// So in a real UAC run those standalone artifacts never actually execute.
// That matters because several of them declare the wrong permission bits when
// they DO run: system/world_writable_files.yaml checks permissions: [-0004]
// (world-READ) and system/group_writable_files.yaml checks [-0040]
// (group-READ), not the write bits their names promise. bodyfile2filelists.sh
// itself checks the write bits correctly. This is presumably a dormant,
// long-unnoticed inconsistency in upstream UAC's own artifact corpus -- it can
// only ever surface by literally running those artifacts, which normal UAC
// never does.
//
// uacscan has no evaluator for arbitrary shell `condition:` clauses, and
// building one for this single, well-understood dependency would be a
// disproportionate amount of machinery for what is really one specific,
// verified fact about how the offline profile is put together. So that fact
// is encoded directly: recognise bodyfile2filelists.yaml, reimplement its
// classification logic against the same per-file data every other rule
// already sees during the walk, and drop the twelve artifacts it shadows.
const KindBodyfileLists Kind = "bodyfile_lists"

// bodyfileListsCommand is the command UAC's own artifact declares.
const bodyfileListsCommand = "bodyfile2filelists.sh"

// shadowedByBodyfileLists names the source artifacts bodyfile2filelists.yaml
// makes redundant in a real UAC run, keyed by artifact.Entry.Source. Verified
// directly against every artifacts/system/*.yaml file: each of these, and
// only these, carries the "skip if my output file already exists" condition
// bodyfile2filelists.yaml's own output satisfies. getcap.yaml and
// immutable_files.yaml are gated on command_exists(...) instead -- a different
// mechanism, not this one -- and are unaffected.
var shadowedByBodyfileLists = map[string]bool{
	"system/suid.yaml":                           true,
	"system/sgid.yaml":                           true,
	"system/hidden_files.yaml":                   true,
	"system/hidden_directories.yaml":             true,
	"system/user_name_unknown_files.yaml":        true,
	"system/user_name_unknown_directories.yaml":  true,
	"system/group_name_unknown_files.yaml":       true,
	"system/group_name_unknown_directories.yaml": true,
	"system/world_writable_files.yaml":           true,
	"system/world_writable_directories.yaml":     true,
	"system/group_writable_files.yaml":           true,
	"system/group_writable_directories.yaml":     true,
}

// compileBodyfileLists recognises bodyfile2filelists.yaml's command. It
// returns nil for anything else, so the caller falls through to compileList's
// HISTFILE recognition and, ultimately, to skipping an unimplemented command
// collector -- the same "recognise or skip" contract every other native
// command reimplementation in this package follows.
//
// The rule carries a single anchor at "/", exactly like the bodyfile stat
// rule itself: this artifact classifies every entry a bodyfile would have,
// not a filtered subset, so there is nothing narrower to anchor it to.
func compileBodyfileLists(e artifact.Entry, doc *artifact.Doc) *Rule {
	if !strings.HasPrefix(strings.TrimSpace(e.Command), bodyfileListsCommand) {
		return nil
	}
	dir := doc.OutputDirectory
	if e.OutputDirectory != "" {
		dir = e.OutputDirectory
	}
	return &Rule{
		ID:        e.ID(),
		Source:    e.Source,
		Kind:      KindBodyfileLists,
		OutputDir: dir,
		anchors:   []anchor{{glob: CompileGlob("/")}},
	}
}

// ApplyBodyfileListsShadowing mirrors what a real UAC run actually does when
// both bodyfile2filelists.yaml and bodyfile/bodyfile.yaml are selected: the
// twelve artifacts it shadows are dropped, matching the condition-gated skip
// they would hit for real. If bodyfile2filelists is selected but
// bodyfile/bodyfile.yaml is not, UAC's own condition on the artifact --
// "if [ -s bodyfile.txt ]" -- would be false (there would be no bodyfile to
// classify), so the KindBodyfileLists rule is dropped instead and the
// standalone artifacts are left to run, matching that fallback path exactly.
//
// This has to run after every rule in the set is compiled: which artifacts
// are shadowed depends on which OTHER artifacts were also selected, which is
// not knowable from any single artifact's own YAML.
func ApplyBodyfileListsShadowing(rs []*Rule) []*Rule {
	hasBodyfileLists, hasBodyfile := false, false
	for _, r := range rs {
		switch {
		case r.Kind == KindBodyfileLists:
			hasBodyfileLists = true
		case r.Kind == KindStat && r.Source == "bodyfile/bodyfile.yaml":
			hasBodyfile = true
		}
	}
	if !hasBodyfileLists {
		return rs
	}

	out := make([]*Rule, 0, len(rs))
	for _, r := range rs {
		switch {
		case !hasBodyfile && r.Kind == KindBodyfileLists:
			continue // no bodyfile to classify; UAC's own condition would skip
		case hasBodyfile && shadowedByBodyfileLists[r.Source]:
			continue // condition-gated out for real; keep bodyfile2filelists' version
		default:
			out = append(out, r)
		}
	}
	return out
}

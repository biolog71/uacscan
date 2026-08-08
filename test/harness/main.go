// Command uacdiff runs the shell UAC and uacscan against the same synthetic
// image and reports every difference between their outputs.
//
// This is the correctness oracle for the rewrite. Unit tests say the code does
// what I think find(1) does; this says whether it does what find(1) actually
// did.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
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
	"uacscan/internal/uacpath"
	"uacscan/internal/walk"
	"uacscan/test/fixture"
	"uacscan/test/uacfull"
)

func main() {
	var (
		uacDir    = flag.String("uac", "", "run against this UAC checkout instead of the embedded copy")
		artifacts = flag.String("artifacts", defaultArtifacts, "comma-separated artifact list passed to both tools")
		work      = flag.String("work", "", "working directory (default: a temporary one)")
		keep      = flag.Bool("keep", false, "keep the working directory")
		image     = flag.String("image", "", "use an existing tree instead of building the fixture")
		verbose   = flag.Bool("v", false, "print every difference, not just a summary")
	)
	flag.Parse()

	resolved, why, err := ResolveUAC(*uacDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "uacdiff: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("uac           : %s (%s)\n", resolved, why)
	if err := run(resolved, *artifacts, *work, *image, *keep, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "uacdiff: %v\n", err)
		os.Exit(1)
	}
}

// The offline artifacts that exercise all four collectors without producing
// output so large that a disagreement is unreadable.
const defaultArtifacts = "bodyfile/bodyfile.yaml," +
	"system/suid.yaml,system/sgid.yaml," +
	"system/world_writable_files.yaml,system/group_writable_files.yaml," +
	"system/hidden_files.yaml,system/hidden_directories.yaml," +
	"hash_executables/hash_executables.yaml," +
	"system/getcap.yaml,system/immutable_files.yaml," +
	"files/shell/bash.yaml,files/shell/common.yaml," +
	"system/user_name_unknown_files.yaml,system/group_name_unknown_files.yaml," +
	"system/user_name_unknown_directories.yaml,system/group_name_unknown_directories.yaml," +
	"system/world_writable_directories.yaml,system/group_writable_directories.yaml," +
	"files/ssh/authorized_keys.yaml,files/ssh/known_hosts.yaml," +
	"files/system/etc.yaml"

func run(uacDir, artifactList, work, image string, keep, verbose bool) error {
	if work == "" {
		d, err := os.MkdirTemp("", "uacdiff-*")
		if err != nil {
			return err
		}
		work = d
		if !keep {
			defer os.RemoveAll(work)
		}
	}
	if err := os.MkdirAll(work, 0755); err != nil {
		return err
	}
	fmt.Printf("work directory: %s\n", work)

	root := image
	if root == "" {
		root = filepath.Join(work, "image")
		if err := os.MkdirAll(root, 0755); err != nil {
			return err
		}
		if err := fixture.Build(root); err != nil {
			return fmt.Errorf("building the fixture: %w", err)
		}
		fmt.Printf("fixture image : %s\n", root)
	}

	uacOut := filepath.Join(work, "uac")
	scanOut := filepath.Join(work, "uacscan")
	for _, d := range []string{uacOut, scanOut} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return err
		}
	}

	fmt.Printf("artifacts     : %s\n\n", artifactList)

	fmt.Println("== running shell UAC ==")
	t0 := time.Now()
	uacResult, err := runUAC(uacDir, artifactList, root, uacOut)
	uacElapsed := time.Since(t0)
	if err != nil {
		return fmt.Errorf("running UAC: %w", err)
	}
	fmt.Printf("   output: %s\n   elapsed: %s\n\n", uacResult, uacElapsed.Round(time.Millisecond))

	fmt.Println("== running uacscan ==")
	t0 = time.Now()
	stats, twoPhase, err := runScan(uacDir, artifactList, root, scanOut)
	scanElapsed := time.Since(t0)
	if err != nil {
		return fmt.Errorf("running uacscan: %w", err)
	}
	fmt.Printf("   %d files visited, %d directories, %d errors\n   elapsed: %s\n\n",
		stats.Files, stats.Dirs, stats.Errors, scanElapsed.Round(time.Millisecond))

	if scanElapsed > 0 {
		fmt.Printf("wall clock    : uac %s, uacscan %s (%.1fx)\n\n",
			uacElapsed.Round(time.Millisecond), scanElapsed.Round(time.Millisecond),
			float64(uacElapsed)/float64(scanElapsed))
	}

	return compare(uacResult, scanOut, root, twoPhase, verbose)
}

// ResolveUAC decides which UAC the comparison runs against.
//
// The embedded copy is the default, so the harness works on a machine that has
// nothing but this repository and always compares against a known version. An
// explicit -uac, or UAC_ROOT, switches to a checkout -- which is what you want
// while changing UAC itself, at the cost of no longer knowing exactly which
// version produced the result.
func ResolveUAC(override string) (dir, why string, err error) {
	if override != "" {
		return override, "specified with -uac", nil
	}
	if r := uacpath.Find(); r != "" && os.Getenv("UAC_ROOT") != "" {
		return r, "checkout from $UAC_ROOT", nil
	}
	d, err := uacfull.Dir()
	if err != nil {
		return "", "", fmt.Errorf("unpacking the embedded UAC: %w", err)
	}
	release, commit := uacfull.Version()
	return d, fmt.Sprintf("embedded %s, commit %s", release, commit), nil
}

// runUAC invokes the shell implementation and returns its output directory.
func runUAC(uacDir, artifactList, root, out string) (string, error) {
	base := "uacout"
	cmd := exec.Command("./uac",
		"-a", artifactList,
		"-m", root,
		"-f", "none",
		"-o", base,
		"-u", // skip the root check: the fixture needs no privilege to read
		out,
	)
	cmd.Dir = uacDir
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if err != nil {
		// UAC exits non-zero for reasons that still produce usable output
		// (artifacts skipped for the OS, unreadable files). Only give up if
		// nothing was written at all.
		tail := buf.String()
		if len(tail) > 2000 {
			tail = tail[len(tail)-2000:]
		}
		if dir, derr := findOutputDir(out, base); derr == nil {
			fmt.Printf("   (uac exited with %v; continuing)\n", err)
			return dir, nil
		}
		return "", fmt.Errorf("%w\n%s", err, tail)
	}
	return findOutputDir(out, base)
}

func findOutputDir(out, base string) (string, error) {
	entries, err := os.ReadDir(out)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), base) {
			return filepath.Join(out, e.Name()), nil
		}
	}
	// -f none may write straight into the destination.
	if _, err := os.Stat(filepath.Join(out, "bodyfile")); err == nil {
		return out, nil
	}
	return "", fmt.Errorf("no UAC output directory under %s", out)
}

// runScan returns the walk statistics and the paths collected by the two-phase
// artifacts, which the comparison needs in order to explain a divergence that
// is intended.
func runScan(uacDir, artifactList, root, out string) (walk.Stats, map[string]bool, error) {
	docs, parseErrs := artifact.LoadDir(filepath.Join(uacDir, "artifacts"))
	for f, err := range parseErrs {
		fmt.Fprintf(os.Stderr, "   warning: %s: %v\n", f, err)
	}

	want := map[string]bool{}
	for _, a := range strings.Split(artifactList, ",") {
		want[strings.TrimSpace(a)] = true
	}

	conf, err := config.Load(filepath.Join(uacDir, "config", "uac.conf"))
	if err != nil {
		return walk.Stats{}, nil, err
	}
	accounts := passwd.Load(root)
	env := &rules.Env{
		MountPoint: root,
		Now:        time.Now(),
		// UAC defaults to the host's OS (it calls uname -s, even offline), so
		// pin the same value here. Letting the two tools resolve the target
		// independently could hand them different rule sets and turn a
		// comparison failure into something meaningless.
		OS:            targetos.Host(),
		EnableMtime:   conf.EnableFindMtime,
		EnableAtime:   conf.EnableFindAtime,
		EnableCtime:   conf.EnableFindCtime,
		HashAlgorithm: conf.HashAlgorithm,
		UserHomes:     accounts.Homes,
		OutputDir:     out,
	}
	if accounts.Known() {
		env.UIDs, env.GIDs = accounts.UIDs, accounts.GIDs
	}

	var compiled []*rules.Rule
	for _, d := range docs {
		if !want[d.Source] {
			continue
		}
		for _, e := range d.Artifacts {
			r, err := rules.Compile(e, d, env)
			if err != nil {
				return walk.Stats{}, nil, err
			}
			if r != nil {
				compiled = append(compiled, r)
			}
		}
	}
	if len(compiled) == 0 {
		return walk.Stats{}, nil, fmt.Errorf("no rules selected")
	}
	fmt.Printf("   %d rules compiled\n", len(compiled))

	store, serr := spool.NewStore(out)
	if serr != nil {
		return walk.Stats{}, nil, serr
	}
	cache := fsref.NewCache(root)
	broker := content.NewBroker()
	ctx := &collector.Context{Cache: cache, Broker: broker, Store: store, Env: env, OutputRoot: out}
	broker.OnError = func(p, c string, err error) { ctx.RecordError(p, c, err) }

	var cs []collector.Collector
	for _, r := range compiled {
		c, err := collector.New(r, ctx)
		if err != nil {
			return walk.Stats{}, nil, err
		}
		cs = append(cs, c)
	}
	w := &walk.Walker{
		Root: root, Cache: cache, Broker: broker,
		Set: rules.NewSet(compiled), Collectors: cs,
		OnError: func(p string, err error) { ctx.RecordError(p, "walk", err) },
	}
	if err := w.Walk(); err != nil {
		return walk.Stats{}, nil, err
	}
	// Paths that only became known during the walk, by reading rc files.
	twoPhase := map[string]bool{}
	for _, r := range compiled {
		if r.FromList {
			for _, p := range ctx.List(r.ListKey) {
				twoPhase[strings.TrimPrefix(p, "/")] = true
			}
		}
	}
	return w.Stats(), twoPhase, store.Close()
}

// ---------------------------------------------------------------------------
// comparison
// ---------------------------------------------------------------------------

type diff struct {
	name         string
	onlyUAC      []string
	onlyScan     []string
	disagree     []string
	sameCount    int
	uacTotal     int
	scanTotal    int
	notCollected bool

	// expected marks a divergence that is intended rather than a defect, with
	// the reason. See ownershipDivergence.
	expected string
}

// ownershipArtifacts depend on an account database.
var ownershipArtifacts = map[string]bool{
	"system/user_name_unknown_files.txt":        true,
	"system/group_name_unknown_files.txt":       true,
	"system/user_name_unknown_directories.txt":  true,
	"system/group_name_unknown_directories.txt": true,
}

// ownershipDivergence explains the one difference that is deliberate.
//
// find -nouser consults the account database of the machine it runs on, so UAC
// answers these artifacts using the *examiner's* passwd file. uacscan reads the
// image's own, which is the only answer that means anything for a mounted
// image -- and when the image has no passwd file at all it declines to answer
// rather than flagging every file. A tree with no /etc/passwd therefore makes
// the two disagree by design.
const ownershipDivergence = "by design: uacscan reads the image's account database, " +
	"which this tree does not have; find -nouser used the host's"

// twoPhaseDivergence explains the second intended difference.
//
// UAC does not prepend the mount point when running a command collector, only
// when running find. Offline, the HISTFILE extraction therefore greps the
// *examiner's* home directories rather than the image's -- visible in UAC's own
// log as "grep: /home/alice/.bashrc: No such file or directory" while the file
// collectors are correctly reading from the image. On a workstation where those
// paths do exist it would be worse than a miss: the examiner's own shell
// history would be collected into the evidence.
//
// uacscan reads the image's rc files, so it finds history files UAC does not.
const twoPhaseDivergence = "by design: UAC does not apply the mount point to command " +
	"collectors, so its HISTFILE lookup reads the examiner's home directories, not the image's"

func compare(uacDir, scanDir, root string, twoPhase map[string]bool, verbose bool) error {
	fmt.Println("== comparison ==")
	var diffs []diff

	_, hasAccounts := os.Stat(filepath.Join(root, "etc/passwd"))
	imageHasAccounts := hasAccounts == nil

	diffs = append(diffs, compareBodyfile(uacDir, scanDir, root))
	for _, f := range []string{
		"system/suid.txt", "system/sgid.txt",
		"system/world_writable_files.txt", "system/group_writable_files.txt",
		"system/hidden_files.txt", "system/hidden_directories.txt",
		"system/user_name_unknown_files.txt", "system/group_name_unknown_files.txt",
		"system/user_name_unknown_directories.txt", "system/group_name_unknown_directories.txt",
		"system/world_writable_directories.txt", "system/group_writable_directories.txt",
		// These reproduce getcap and lsattr output, so they are compared as
		// whole lines rather than as bare paths.
		"system/getcap.txt", "system/immutable_files.txt",
	} {
		d := comparePathList(uacDir, scanDir, root, f)
		if !imageHasAccounts && ownershipArtifacts[f] {
			d.expected = ownershipDivergence
		}
		diffs = append(diffs, d)
	}
	for _, algo := range []string{"md5", "sha1", "sha256"} {
		diffs = append(diffs, compareHashes(uacDir, scanDir, root,
			"hash_executables/hash_executables."+algo))
	}
	collected := compareCollectedTree(uacDir, scanDir)
	if len(twoPhase) > 0 && !liveCollection(root) && onlyTwoPhase(collected.onlyScan, twoPhase) {
		collected.expected = twoPhaseDivergence
	}
	diffs = append(diffs, collected)

	failures := 0
	for _, d := range diffs {
		status := "OK"
		n := len(d.onlyUAC) + len(d.onlyScan) + len(d.disagree)
		if d.notCollected {
			status = "SKIP (neither tool produced it)"
		} else if n > 0 && d.expected != "" {
			status = fmt.Sprintf("%d EXPECTED (%s)", n, d.expected)
		} else if n > 0 {
			status = fmt.Sprintf("%d DIFFERENCES", n)
			failures++
		}
		fmt.Printf("\n%-34s uac=%-6d scan=%-6d agree=%-6d %s\n",
			d.name, d.uacTotal, d.scanTotal, d.sameCount, status)

		show := func(label string, items []string) {
			if len(items) == 0 {
				return
			}
			limit := len(items)
			if !verbose && limit > 8 {
				limit = 8
			}
			for _, s := range items[:limit] {
				fmt.Printf("    %s %s\n", label, s)
			}
			if limit < len(items) {
				fmt.Printf("    ... %d more (use -v)\n", len(items)-limit)
			}
		}
		show("only-uac ", d.onlyUAC)
		show("only-scan", d.onlyScan)
		show("differs  ", d.disagree)
	}

	fmt.Println()
	if failures > 0 {
		return fmt.Errorf("%d output(s) differ", failures)
	}
	fmt.Println("all compared outputs agree")
	return nil
}

// stripMount removes the mount point from a path. UAC's bodyfile and find
// outputs carry it because find was given the prefixed path; uacscan records
// image-relative paths, so one side has to be normalised for comparison.
// liveCollection reports whether the comparison ran against the running system,
// where UAC's command collectors are correct.
func liveCollection(root string) bool {
	return root == "" || root == "/"
}

// onlyTwoPhase reports whether every extra file uacscan collected came from the
// two-phase artifacts. Anything else is a real difference.
func onlyTwoPhase(onlyScan []string, twoPhase map[string]bool) bool {
	if len(onlyScan) == 0 {
		return false
	}
	for _, p := range onlyScan {
		if !twoPhase[strings.TrimPrefix(p, "[root]/")] {
			return false
		}
	}
	return true
}

func stripMount(p, root string) string {
	root = strings.TrimSuffix(root, "/")
	if strings.HasPrefix(p, root+"/") {
		return p[len(root):]
	}
	if p == root {
		return "/"
	}
	return p
}

func compareBodyfile(uacDir, scanDir, root string) diff {
	d := diff{name: "bodyfile"}
	uacLines, uacOK := readLines(filepath.Join(uacDir, "bodyfile/bodyfile.txt"))
	scanLines, scanOK := readLines(filepath.Join(scanDir, "bodyfile/bodyfile.txt"))
	if !uacOK && !scanOK {
		d.notCollected = true
		return d
	}

	parse := func(lines []string, strip bool) map[string][]string {
		out := map[string][]string{}
		for _, l := range lines {
			f := strings.Split(l, "|")
			if len(f) < 11 {
				continue
			}
			name := f[1]
			if strip {
				// A symlink line is "path -> target"; normalise both halves.
				if i := strings.Index(name, " -> "); i >= 0 {
					name = stripMount(name[:i], root) + " -> " + name[i+4:]
				} else {
					name = stripMount(name, root)
				}
			}
			out[name] = f
		}
		return out
	}
	u := parse(uacLines, true)
	s := parse(scanLines, false)
	d.uacTotal, d.scanTotal = len(u), len(s)

	// Field 2 is the inode, 3 the mode string, 4/5 uid/gid, 6 size,
	// 7/8/9 atime/mtime/ctime, 10 birth time.
	fieldNames := map[int]string{2: "inode", 3: "mode", 4: "uid", 5: "gid", 6: "size", 8: "mtime", 9: "ctime", 10: "crtime"}
	for name, uf := range u {
		sf, ok := s[name]
		if !ok {
			d.onlyUAC = append(d.onlyUAC, name)
			continue
		}
		var bad []string
		for idx, label := range fieldNames {
			if uf[idx] != sf[idx] {
				bad = append(bad, fmt.Sprintf("%s uac=%s scan=%s", label, uf[idx], sf[idx]))
			}
		}
		if len(bad) > 0 {
			sort.Strings(bad)
			d.disagree = append(d.disagree, name+": "+strings.Join(bad, ", "))
		} else {
			d.sameCount++
		}
	}
	for name := range s {
		if _, ok := u[name]; !ok {
			d.onlyScan = append(d.onlyScan, name)
		}
	}
	sortAll(&d)
	return d
}

func comparePathList(uacDir, scanDir, root, rel string) diff {
	d := diff{name: rel}
	uacLines, uacOK := readLines(filepath.Join(uacDir, rel))
	scanLines, scanOK := readLines(filepath.Join(scanDir, rel))
	if !uacOK && !scanOK {
		d.notCollected = true
		return d
	}
	u := map[string]bool{}
	for _, l := range uacLines {
		u[stripMount(strings.TrimSpace(l), root)] = true
	}
	s := map[string]bool{}
	for _, l := range scanLines {
		s[strings.TrimSpace(l)] = true
	}
	d.uacTotal, d.scanTotal = len(u), len(s)
	for p := range u {
		if s[p] {
			d.sameCount++
		} else {
			d.onlyUAC = append(d.onlyUAC, p)
		}
	}
	for p := range s {
		if !u[p] {
			d.onlyScan = append(d.onlyScan, p)
		}
	}
	sortAll(&d)
	return d
}

// compareHashes compares digest lists keyed by path. Both tools write the
// md5sum-style "<digest>  <path>" form.
func compareHashes(uacDir, scanDir, root, rel string) diff {
	d := diff{name: rel}
	uacLines, uacOK := readLines(filepath.Join(uacDir, rel))
	scanLines, scanOK := readLines(filepath.Join(scanDir, rel))
	if !uacOK && !scanOK {
		d.notCollected = true
		return d
	}
	parse := func(lines []string, strip bool) map[string]string {
		out := map[string]string{}
		for _, l := range lines {
			parts := strings.SplitN(l, "  ", 2)
			if len(parts) != 2 {
				continue
			}
			p := strings.TrimSpace(parts[1])
			if strip {
				p = stripMount(p, root)
			}
			out[p] = parts[0]
		}
		return out
	}
	u := parse(uacLines, true)
	s := parse(scanLines, false)
	d.uacTotal, d.scanTotal = len(u), len(s)
	for p, uh := range u {
		sh, ok := s[p]
		if !ok {
			d.onlyUAC = append(d.onlyUAC, p)
			continue
		}
		if uh != sh {
			d.disagree = append(d.disagree, fmt.Sprintf("%s: uac=%s scan=%s", p, uh, sh))
		} else {
			d.sameCount++
		}
	}
	for p := range s {
		if _, ok := u[p]; !ok {
			d.onlyScan = append(d.onlyScan, p)
		}
	}
	sortAll(&d)
	return d
}

// compareCollectedTree checks the files each tool copied out: same set of
// paths, and identical bytes for the ones both collected.
func compareCollectedTree(uacDir, scanDir string) diff {
	d := diff{name: "collected files ([root])"}
	u := hashTree(filepath.Join(uacDir, "[root]"))
	s := hashTree(filepath.Join(scanDir, "[root]"))
	if len(u) == 0 && len(s) == 0 {
		d.notCollected = true
		return d
	}
	d.uacTotal, d.scanTotal = len(u), len(s)
	for p, uh := range u {
		sh, ok := s[p]
		if !ok {
			d.onlyUAC = append(d.onlyUAC, p)
			continue
		}
		if uh != sh {
			d.disagree = append(d.disagree, p+": content differs")
		} else {
			d.sameCount++
		}
	}
	for p := range s {
		if _, ok := u[p]; !ok {
			d.onlyScan = append(d.onlyScan, p)
		}
	}
	sortAll(&d)
	return d
}

func hashTree(root string) map[string]string {
	out := map[string]string{}
	filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		fi, err := e.Info()
		if err != nil || !fi.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		out[rel] = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	return out
}

func readLines(path string) ([]string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		if l := sc.Text(); l != "" {
			out = append(out, l)
		}
	}
	return out, true
}

func sortAll(d *diff) {
	sort.Strings(d.onlyUAC)
	sort.Strings(d.onlyScan)
	sort.Strings(d.disagree)
}

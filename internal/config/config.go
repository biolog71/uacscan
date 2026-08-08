// Package config reads UAC's uac.conf.
//
// Several things that look like collector behaviour are actually configuration,
// and getting them from the same file UAC reads is the only way the two tools
// can be expected to agree. The differential harness found both of the
// surprises here: hash_algorithm defaults to md5 and sha1 (not sha256), and
// enable_find_atime defaults to false, so access times do not participate in
// the date range even though find would happily test them.
package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Config is the subset of uac.conf that changes what gets collected.
type Config struct {
	ExcludePathPattern []string
	ExcludeNamePattern []string
	ExcludeFileSystem  []string
	HashAlgorithm      []string
	MaxDepth           int

	EnableFindMtime bool
	EnableFindAtime bool
	EnableFindCtime bool
}

// Default matches the values shipped in UAC's config/uac.conf.
func Default() *Config {
	return &Config{
		ExcludeFileSystem: []string{"9p", "afs", "autofs", "cifs", "davfs", "fuse",
			"kernfs", "nfs", "nfs4", "rpc_pipefs", "smbfs", "sysfs"},
		HashAlgorithm:   []string{"md5", "sha1"},
		EnableFindMtime: true,
		EnableFindAtime: false,
		EnableFindCtime: true,
	}
}

// Load reads a uac.conf, falling back to the defaults for anything absent. A
// missing file is not an error: the defaults are the shipped configuration.
func Load(path string) (*Config, error) {
	c := Default()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "exclude_path_pattern":
			c.ExcludePathPattern = parseList(val)
		case "exclude_name_pattern":
			c.ExcludeNamePattern = parseList(val)
		case "exclude_file_system":
			c.ExcludeFileSystem = parseList(val)
		case "hash_algorithm":
			if l := parseList(val); len(l) > 0 {
				c.HashAlgorithm = l
			}
		case "max_depth":
			if n, err := strconv.Atoi(val); err == nil {
				c.MaxDepth = n
			}
		case "enable_find_mtime":
			c.EnableFindMtime = val == "true"
		case "enable_find_atime":
			c.EnableFindAtime = val == "true"
		case "enable_find_ctime":
			c.EnableFindCtime = val == "true"
		}
	}
	return c, sc.Err()
}

func parseList(val string) []string {
	val = strings.TrimSpace(val)
	if !strings.HasPrefix(val, "[") {
		if val == "" {
			return nil
		}
		return []string{val}
	}
	val = strings.TrimSuffix(strings.TrimPrefix(val, "["), "]")
	var out []string
	for _, p := range strings.Split(val, ",") {
		if p = strings.Trim(strings.TrimSpace(p), `"'`); p != "" {
			out = append(out, p)
		}
	}
	return out
}

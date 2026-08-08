package rules

import (
	"reflect"
	"testing"
)

func TestParseEveryRealHistfileCommand(t *testing.T) {
	// Every extraction command in UAC's shell artifacts, verbatim.
	cmds := []string{
		`grep -E "^HISTFILE=.*" /etc/profile | sed -e 's|.*HISTFILE=||' -e 's|^~/|%user_home%/|'`,
		`grep -E "HISTFILE=.*" %user_home%/.bashrc %user_home%/.bash_profile %user_home%/.profile /etc/bash.bashrc | sed -e 's|.*HISTFILE=||' -e 's|^~/|%user_home%/|'`,
		`grep -E "HISTFILE=.*" %user_home%/.config/fish/config.fish /etc/fish/config.fish | sed -e 's|.*HISTFILE=||' -e 's|^~/|%user_home%/|'`,
		`grep -E "HISTFILE=.*" %user_home%/.config/oil/oshrc %user_home%/.config/oil/yshrc | sed -e 's|.*HISTFILE=||' -e 's|^~/|%user_home%/|'`,
		`grep -E "HISTFILE=.*" %user_home%/.cshrc %user_home%/.tcshrc %user_home%/.login %user_home%/.login_conf %user_home%/.logout /etc/csh.cshrc /etc/csh.login /etc/csh.logout | sed -e 's|.*HISTFILE=||' -e 's|^~/|%user_home%/|'`,
		`grep -E "^HISTFILE=.*" %user_home%/.profile  | sed -e 's|.*HISTFILE=||' -e 's|^~/|%user_home%/|'`,
		`grep -E "HISTFILE=.*" %user_home%/.profile | sed -e 's|.*HISTFILE=||' -e 's|^~/|%user_home%/|'`,
		`grep -E "^HISTFILE=.*" %user_home%/.shrc %user_home%/.kshrc %user_home%/.profile  | sed -e 's|.*HISTFILE=||' -e 's|^~/|%user_home%/|'`,
		`grep -E "^HISTFILE=.*" %user_home%/.zlogin %user_home%/.zprofile %user_home%/.zshenv %user_home%/.zshrc /etc/zshenv /etc/zprofile /etc/zshrc /etc/zlogin | sed -e 's|.*HISTFILE=||' -e 's|^~/|%user_home%/|'`,
		`grep -E "XONSH_HISTORY_FILE=.*" %user_home%/.xonshrc /etc/xonshrc | sed -e 's|.*XONSH_HISTORY_FILE=||' -e 's|^~/|%user_home%/|'`,
	}
	for _, c := range cmds {
		spec, ok := ParseHistfileCommand(c)
		if !ok {
			t.Errorf("failed to parse: %s", c)
			continue
		}
		if spec.Var == "" || len(spec.Files) == 0 {
			t.Errorf("empty spec for: %s", c)
		}
	}
}

// Anything that is not the recognised shape must be refused, not guessed at.
func TestUnrecognisedCommandsAreRefused(t *testing.T) {
	for _, c := range []string{
		"ps aux",
		"cat /etc/passwd",
		`grep -E "HISTFILE=.*" /etc/profile`, // no sed pipeline
		`rm -rf / | sed -e 's|.*HISTFILE=||' -e 's|^~/|/home/x/|'`,
		"",
	} {
		if _, ok := ParseHistfileCommand(c); ok {
			t.Errorf("wrongly accepted: %q", c)
		}
	}
}

func TestExtractAssignments(t *testing.T) {
	spec, ok := ParseHistfileCommand(
		`grep -E "HISTFILE=.*" /x | sed -e 's|.*HISTFILE=||' -e 's|^~/|/home/a/|'`)
	if !ok {
		t.Fatal("setup command did not parse")
	}
	content := []byte(`# a comment
export PS1='$ '
HISTFILE=~/.hidden_history
export HISTFILE="/var/log/quoted_history"
  HISTFILE='/tmp/single'
HISTFILE=/with/trailing   # explains itself
HISTSIZE=1000
nothing here
`)
	got := spec.ExtractAssignments(content)
	want := []string{
		"~/.hidden_history",
		"/var/log/quoted_history",
		"/tmp/single",
		"/with/trailing",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExtractAssignments = %#v, want %#v", got, want)
	}
}

func TestAnchoredExtractionIgnoresIndentedAssignments(t *testing.T) {
	anchored, _ := ParseHistfileCommand(
		`grep -E "^HISTFILE=.*" /x | sed -e 's|.*HISTFILE=||' -e 's|^~/|/home/a/|'`)
	loose, _ := ParseHistfileCommand(
		`grep -E "HISTFILE=.*" /x | sed -e 's|.*HISTFILE=||' -e 's|^~/|/home/a/|'`)

	content := []byte("export HISTFILE=/indented\nHISTFILE=/at_start\n")
	if got := anchored.ExtractAssignments(content); !reflect.DeepEqual(got, []string{"/at_start"}) {
		t.Errorf("anchored = %#v, want [/at_start]", got)
	}
	if got := loose.ExtractAssignments(content); len(got) != 2 {
		t.Errorf("unanchored = %#v, want both", got)
	}
}

func TestResolveHistfile(t *testing.T) {
	cases := []struct {
		value, home, want string
		ok                bool
	}{
		{"~/.hist", "/home/alice", "/home/alice/.hist", true},
		{"~/.hist", "/home/alice/", "/home/alice/.hist", true},
		{"/var/log/hist", "/home/alice", "/var/log/hist", true},
		// UAC's sed only rewrites "~/", so anything else would have reached cp
		// as a relative path and failed. Report it rather than reproduce it.
		{".bash_history", "/home/alice", "", false},
		{"$HOME/.hist", "/home/alice", "", false},
		{"", "/home/alice", "", false},
		{"~/.hist", "", "", false},
	}
	for _, tc := range cases {
		got, ok := ResolveHistfile(tc.value, tc.home)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ResolveHistfile(%q, %q) = (%q, %v), want (%q, %v)",
				tc.value, tc.home, got, ok, tc.want, tc.ok)
		}
	}
}

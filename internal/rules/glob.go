package rules

import "strings"

// Glob implements fnmatch(3) without FNM_PATHNAME, which is what find(1) uses
// for -path and -name: '*' spans '/' freely. Go's path/filepath.Match stops '*'
// at a separator, so it cannot be used here -- a pattern like "*/.git/hooks/*"
// would never match.
type Glob struct {
	pat string
	// literal is the leading run of non-metacharacters. Comparing it first
	// rejects the overwhelming majority of candidates without entering the
	// matcher at all.
	literal string
	anyPos  bool // pattern starts with a metacharacter
}

func CompileGlob(pat string) Glob {
	g := Glob{pat: pat}
	i := strings.IndexAny(pat, "*?[")
	switch {
	case i < 0:
		g.literal = pat
	case i == 0:
		g.anyPos = true
	default:
		g.literal = pat[:i]
	}
	return g
}

func (g Glob) Pattern() string { return g.pat }

// IsLiteral reports whether the pattern has no metacharacters.
func (g Glob) IsLiteral() bool { return !g.anyPos && g.literal == g.pat }

func (g Glob) Match(s string) bool {
	if !g.anyPos && g.literal != "" && !strings.HasPrefix(s, g.literal) {
		return false
	}
	return fnmatch(g.pat, s)
}

// fnmatch is an iterative backtracking matcher: linear in the common case,
// and it cannot blow the stack on a pathological pattern the way recursion can.
func fnmatch(pat, s string) bool {
	var (
		p, i       int
		starPat    = -1
		starStr    int
		patLen     = len(pat)
		sLen       = len(s)
		matchedSet bool
	)
	for i < sLen {
		if p < patLen {
			switch pat[p] {
			case '*':
				starPat, starStr = p, i
				p++
				continue
			case '?':
				p++
				i++
				continue
			case '[':
				if end, ok := matchClass(pat, p, s[i]); ok {
					p = end
					i++
					matchedSet = true
					continue
				} else if end > 0 {
					// well-formed class that did not match
					if starPat >= 0 {
						p = starPat + 1
						starStr++
						i = starStr
						continue
					}
					return false
				}
				// unterminated '[': treat as a literal
				fallthrough
			default:
				if pat[p] == s[i] {
					p++
					i++
					continue
				}
			}
		}
		if starPat >= 0 {
			p = starPat + 1
			starStr++
			i = starStr
			continue
		}
		return false
	}
	_ = matchedSet
	for p < patLen && pat[p] == '*' {
		p++
	}
	return p == patLen
}

// matchClass evaluates a [...] bracket expression at pat[p]. It returns the
// index just past the class and whether c matched. A zero end means the class
// was unterminated.
func matchClass(pat string, p int, c byte) (end int, matched bool) {
	q := p + 1
	negate := false
	if q < len(pat) && (pat[q] == '!' || pat[q] == '^') {
		negate = true
		q++
	}
	found := false
	first := true
	for q < len(pat) {
		if pat[q] == ']' && !first {
			q++
			if negate {
				return q, !found
			}
			return q, found
		}
		first = false
		if q+2 < len(pat) && pat[q+1] == '-' && pat[q+2] != ']' {
			if c >= pat[q] && c <= pat[q+2] {
				found = true
			}
			q += 3
			continue
		}
		if pat[q] == c {
			found = true
		}
		q++
	}
	return 0, false
}

// Package version compares the dotted release numbers that runtimes report
// ("v22.23.4", "1.4.4", "8.3.36"). Package versions inside lockfiles are
// compared by OSV's own ecosystem-aware matcher, never by this package.
package version

import (
	"strconv"
	"strings"
)

// V is a parsed dotted version. Missing parts are zero.
type V struct {
	Parts []int
	Raw   string
}

// Parse reads the leading dotted number from s ("v22.23.4", "Python 3.11.15",
// "bun 1.4.4" → 22.23.4, 3.11.15, 1.4.4). ok is false when there is none.
func Parse(s string) (V, bool) {
	s = strings.TrimSpace(s)
	start := strings.IndexFunc(s, func(r rune) bool { return r >= '0' && r <= '9' })
	if start < 0 {
		return V{Raw: s}, false
	}
	rest := s[start:]
	end := strings.IndexFunc(rest, func(r rune) bool { return !(r >= '0' && r <= '9') && r != '.' })
	if end >= 0 {
		rest = rest[:end]
	}
	rest = strings.Trim(rest, ".")
	var parts []int
	for _, p := range strings.Split(rest, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		parts = append(parts, n)
	}
	if len(parts) == 0 {
		return V{Raw: s}, false
	}
	return V{Parts: parts, Raw: rest}, true
}

func (v V) at(i int) int {
	if i < len(v.Parts) {
		return v.Parts[i]
	}
	return 0
}

// Compare returns -1, 0 or 1.
func Compare(a, b V) int {
	n := len(a.Parts)
	if len(b.Parts) > n {
		n = len(b.Parts)
	}
	for i := 0; i < n; i++ {
		switch {
		case a.at(i) < b.at(i):
			return -1
		case a.at(i) > b.at(i):
			return 1
		}
	}
	return 0
}

// Branch returns the release line of v: "22" for branch "major",
// "1.2" for "minor", "" for "none" (a single line).
func Branch(v V, branch string) string {
	switch branch {
	case "major":
		return strconv.Itoa(v.at(0))
	case "minor":
		return strconv.Itoa(v.at(0)) + "." + strconv.Itoa(v.at(1))
	default:
		return ""
	}
}

// Status of an installed version against a list of fixed releases.
type Status string

const (
	Fixed       Status = "fixed"          // at or above the fixed release of its line
	Vulnerable  Status = "vulnerable"     // below the fixed release of its line
	NoFixInLine Status = "no-fix-in-line" // older line with no fixed release listed
	Unknown     Status = "unknown"        // version could not be read
)

// Against decides the Status of installed against the fixed releases, where
// fixed releases are grouped into lines by branch ("major", "minor", "none").
// It also returns the fixed release that applies, if any.
func Against(installed string, fixed []string, branch string) (Status, string) {
	v, ok := Parse(installed)
	if !ok {
		return Unknown, ""
	}
	line := Branch(v, branch)
	var newest V
	haveNewest := false
	for _, f := range fixed {
		fv, ok := Parse(f)
		if !ok {
			continue
		}
		if !haveNewest || Compare(fv, newest) > 0 {
			newest, haveNewest = fv, true
		}
		if Branch(fv, branch) == line {
			if Compare(v, fv) >= 0 {
				return Fixed, fv.Raw
			}
			return Vulnerable, fv.Raw
		}
	}
	if haveNewest && Compare(v, newest) >= 0 {
		// A newer line than any listed: it postdates the fix.
		return Fixed, ""
	}
	if haveNewest {
		return NoFixInLine, newest.Raw
	}
	return Unknown, ""
}

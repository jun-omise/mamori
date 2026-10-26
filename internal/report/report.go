// Package report holds what a scan saw and found, and renders it.
//
// A report always has three parts: what was scanned (so a reader can tell
// what "no findings" covers), the findings, and the blind spots — things
// mamori tried to read and could not. An empty findings list with blind spots
// is not a clean result, and the exit code says so.
package report

import (
	"sort"
	"time"

	"github.com/jun-omise/mamori/internal/egress"
)

// Report is one run of mamori.
type Report struct {
	Tool       string           `json:"tool"`
	Version    string           `json:"version"`
	Started    time.Time        `json:"started"`
	Finished   time.Time        `json:"finished"`
	Mode       string           `json:"mode"`
	Targets    []Target         `json:"targets"`
	Findings   []Finding        `json:"findings"`
	BlindSpots []BlindSpot      `json:"blind_spots"`
	Disclosure []Disclosure     `json:"patch_the_planet"`
	Notes      []string         `json:"notes,omitempty"`
	Egress     []egress.Contact `json:"egress"`
}

// Target is one thing that was scanned: a local folder, a GitHub repository,
// or this machine's runtimes.
type Target struct {
	Kind  string `json:"kind"` // local | github | runtimes
	Name  string `json:"name"`
	Files []File `json:"files,omitempty"`
	// Runtimes lists the runtimes found on this machine (kind runtimes).
	Runtimes []Runtime `json:"runtimes,omitempty"`
	// Extra facts about the target, e.g. Dependabot's own alert count.
	Facts map[string]string `json:"facts,omitempty"`
}

// File is one lockfile or manifest that was read.
type File struct {
	Path      string `json:"path"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Packages  int    `json:"packages"`
}

// Runtime is one runtime binary found on this machine.
type Runtime struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

// Finding is one concrete problem.
type Finding struct {
	Kind      string   `json:"kind"` // package | malicious | runtime
	Target    string   `json:"target"`
	Location  string   `json:"location"`
	Ecosystem string   `json:"ecosystem,omitempty"`
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	IDs       []string `json:"ids"`
	Severity  string   `json:"severity"` // critical | high | medium | low | unknown
	Summary   string   `json:"summary"`
	Fixed     []string `json:"fixed,omitempty"`
	KEV       bool     `json:"known_exploited"`
	// PatchThePlanet is the disclosure id when the finding comes from it.
	PatchThePlanet string `json:"patch_the_planet,omitempty"`
	Advice         string `json:"advice,omitempty"`
}

// BlindSpot is something mamori could not read or could not judge.
type BlindSpot struct {
	Target string `json:"target"`
	Path   string `json:"path,omitempty"`
	// Code names the kind of blind spot; renderers translate it.
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// Disclosure is one Patch the Planet disclosure and what this run could check.
type Disclosure struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	CVEs     []string `json:"cves"`
	URL      string   `json:"url"`
	Checked  []string `json:"checked"`   // products checked on this run
	Manual   []string `json:"unchecked"` // products the reader must check by hand
	Affected int      `json:"affected"`  // findings that came from it
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

// Sort orders findings: exploited first, then malicious, then by severity.
func (r *Report) Sort() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if (a.Kind == "malicious") != (b.Kind == "malicious") {
			return a.Kind == "malicious"
		}
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.Package < b.Package
	})
}

// Counts returns the number of findings per severity.
func (r *Report) Counts() map[string]int {
	c := map[string]int{}
	for _, f := range r.Findings {
		c[f.Severity]++
	}
	return c
}

// ExitCode: 0 clean, 1 findings, 3 no findings but blind spots.
// (2 is reserved for errors that stopped the scan.)
func (r *Report) ExitCode() int {
	switch {
	case len(r.Findings) > 0:
		return 1
	case len(r.BlindSpots) > 0:
		return 3
	default:
		return 0
	}
}

// SeverityFromScore turns a CVSS base score into a label.
func SeverityFromScore(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

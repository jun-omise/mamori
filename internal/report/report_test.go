package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestExitCodeNeverCallsBlindnessClean(t *testing.T) {
	r := &Report{}
	if r.ExitCode() != 0 {
		t.Error("empty report should be 0")
	}
	r.BlindSpots = []BlindSpot{{Target: "x", Code: "no-db"}}
	if r.ExitCode() != 3 {
		t.Error("blind spots without findings must be 3, not 0")
	}
	r.Findings = []Finding{{Severity: "low"}}
	if r.ExitCode() != 1 {
		t.Error("findings must be 1")
	}
}

func TestSortPutsExploitedAndMaliciousFirst(t *testing.T) {
	r := &Report{Findings: []Finding{
		{Package: "a", Severity: "critical"},
		{Package: "b", Severity: "low", KEV: true},
		{Package: "c", Severity: "medium", Kind: "malicious"},
		{Package: "d", Severity: "high"},
	}}
	r.Sort()
	var order []string
	for _, f := range r.Findings {
		order = append(order, f.Package)
	}
	if strings.Join(order, "") != "bcad" {
		t.Errorf("order = %v, want b (KEV), c (malicious), a, d", order)
	}
}

func TestRenderersShowAllThreeParts(t *testing.T) {
	r := &Report{
		Tool: "mamori", Mode: "offline",
		Targets:    []Target{{Kind: "local", Name: "/repo", Files: []File{{Path: "bun.lock", Ecosystem: "npm", Packages: 3}}}},
		Findings:   []Finding{{Kind: "package", Package: "seroval", Version: "1.5.2", IDs: []string{"GHSA-mv8w-475r-vwqw"}, Severity: "critical", Fixed: []string{"1.5.3"}, KEV: true}},
		BlindSpots: []BlindSpot{{Target: "github:o/r", Code: "graph-blind"}},
	}
	for _, lang := range []Lang{"ja", "en"} {
		var text, md bytes.Buffer
		Text(&text, r, lang)
		Markdown(&md, r, lang)
		for name, out := range map[string]string{"text": text.String(), "markdown": md.String()} {
			for _, want := range []string{"bun.lock", "seroval", "1.5.3", "GHSA-mv8w-475r-vwqw", "github:o/r"} {
				if !strings.Contains(out, want) {
					t.Errorf("%s/%s missing %q", lang, name, want)
				}
			}
		}
	}
	var buf bytes.Buffer
	Text(&buf, r, "ja")
	if !strings.Contains(buf.String(), "Dependabot の警告が少なくても安全とは言えません") {
		t.Error("blind-spot codes should be translated")
	}
}

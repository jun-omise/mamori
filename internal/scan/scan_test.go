package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWalkClassifiesAndSkips(t *testing.T) {
	root := t.TempDir()
	write(t, root, "web/package.json", `{}`)
	write(t, root, "web/bun.lock", `{}`)
	write(t, root, "api/pyproject.toml", ``)
	write(t, root, "old/bun.lockb", "\x00")
	write(t, root, "tools/requirements-dev.txt", "a==1\n")
	write(t, root, "web/node_modules/x/package-lock.json", `{}`)
	write(t, root, ".devcontainer/yarn.lock", ``)
	write(t, root, "desktop/build/npm/package-lock.json", `{}`)

	got, skipped, _, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (node_modules)", skipped)
	}
	kinds := map[string]string{}
	for _, c := range got {
		kinds[c.Rel] = c.Kind
	}
	want := map[string]string{
		"web/package.json": "manifest", "web/bun.lock": "lockfile", "api/pyproject.toml": "manifest",
		"old/bun.lockb": "unreadable", "tools/requirements-dev.txt": "lockfile",
		// Hidden folders and build outputs can hold real lockfiles; only
		// installed copies (node_modules) are skipped, and that is counted.
		".devcontainer/yarn.lock": "lockfile", "desktop/build/npm/package-lock.json": "lockfile",
	}
	for k, v := range want {
		if kinds[k] != v {
			t.Errorf("%s: got %q want %q", k, kinds[k], v)
		}
	}
	if len(kinds) != len(want) {
		t.Errorf("only node_modules should be skipped; got %v", kinds)
	}
}

func TestBlindSpotsForUnpinnedAndUnreadable(t *testing.T) {
	cands := []Candidate{
		{Rel: "web/package.json", Kind: "manifest"},
		{Rel: "web/bun.lock", Kind: "lockfile"},
		{Rel: "api/pyproject.toml", Kind: "manifest"},
		{Rel: "old/bun.lockb", Kind: "unreadable"},
	}
	// No lockfile paths are passed to OSV here (the lockfile does not exist
	// on disk), so only mamori's own checks run.
	res, err := Dir(Options{Mode: StrictOffline, CacheDir: t.TempDir()}, "t", t.TempDir(), cands[2:], func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]string{}
	for _, b := range res.BlindSpots {
		codes[b.Path] = b.Code
	}
	if codes["api/pyproject.toml"] != "no-lockfile" || codes["old/bun.lockb"] != "unreadable-format" {
		t.Errorf("blind spots = %v", codes)
	}
	if got := unpinnedManifests("t", cands, func(s string) string { return s }); len(got) != 1 || got[0].Path != "api/pyproject.toml" {
		t.Errorf("package.json next to bun.lock is pinned; only pyproject.toml should be flagged, got %+v", got)
	}
}

// Without a local database OSV-Scanner returns "no vulnerabilities" and only
// logs the problem. mamori must report it, never a clean result.
func TestMissingDatabaseIsABlindSpotNotAPass(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package-lock.json", `{
  "name": "x", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": {"name": "x", "dependencies": {"left-pad": "1.0.0"}},
    "node_modules/left-pad": {"version": "1.0.0"}
  }
}`)
	cands, _, _, _ := Walk(root)
	res, err := Dir(Options{Mode: StrictOffline, CacheDir: t.TempDir()}, "t", root, cands, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || res.Files[0].Packages == 0 {
		t.Fatalf("lockfile should still be inventoried: %+v", res.Files)
	}
	found := false
	for _, b := range res.BlindSpots {
		if b.Code == "no-db" && strings.Contains(b.Reason, "npm") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing npm database must be a blind spot; got %+v", res.BlindSpots)
	}
}

func TestIgnoreFileIsAlwaysNamed(t *testing.T) {
	root := t.TempDir()
	write(t, root, "osv-scanner.toml", "[[IgnoredVulns]]\nid = \"X\"\n\n[[IgnoredVulns]]\nid = \"Y\"\n")
	cands, _, _, _ := Walk(root)
	if len(cands) != 1 || cands[0].Kind != "config" {
		t.Fatalf("candidates = %+v", cands)
	}
	res, err := Dir(Options{Mode: StrictOffline, CacheDir: t.TempDir()}, "t", root, cands, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Ignores) != 1 || !strings.Contains(res.Ignores[0], "2 ignore rule(s)") {
		t.Errorf("ignores = %v", res.Ignores)
	}
}

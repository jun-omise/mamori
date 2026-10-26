// Package scan runs OSV-Scanner's matcher over a folder of lockfiles and
// turns its results into report findings, inventory and blind spots.
//
// Matching is OSV's, not ours: mamori never decides by itself whether a
// package version is affected.
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/jun-omise/mamori/internal/report"
)

// Mode is how vulnerabilities are matched.
type Mode string

const (
	// Offline downloads the public OSV database (only when it changed) and
	// matches on this machine. Package lists never leave it.
	Offline Mode = "offline"
	// StrictOffline matches against the cached database without any network.
	StrictOffline Mode = "strict-offline"
	// Online queries api.osv.dev, which sends package names and versions.
	Online Mode = "online"
)

// Options configure a scan.
type Options struct {
	Mode     Mode
	CacheDir string // the OSV databases live under CacheDir/osv
	HTTP     *http.Client
	// Log receives OSV-Scanner's own log (nil discards it). Errors are also
	// collected and reported as blind spots either way.
	Log slog.Handler
}

// Lockfiles are the file names OSV-Scanner reads with resolved versions.
var Lockfiles = map[string]string{
	"bun.lock": "npm", "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "pnpm-lock.yaml": "npm", "yarn.lock": "npm",
	"uv.lock": "PyPI", "poetry.lock": "PyPI", "Pipfile.lock": "PyPI", "pdm.lock": "PyPI", "pylock.toml": "PyPI", "requirements.txt": "PyPI",
	"Cargo.lock": "crates.io", "go.mod": "Go", "Gemfile.lock": "RubyGems", "gems.locked": "RubyGems",
	"composer.lock": "Packagist", "packages.lock.json": "NuGet", "packages.config": "NuGet",
	"gradle.lockfile": "Maven", "buildscript-gradle.lockfile": "Maven", "pom.xml": "Maven",
	"pubspec.lock": "Pub", "mix.lock": "Hex", "renv.lock": "CRAN", "conan.lock": "ConanCenter",
	"cabal.project.freeze": "Hackage", "stack.yaml.lock": "Hackage",
}

// Manifests declare dependencies without pinning them. Alone, they do not
// say which versions are installed.
var Manifests = map[string][]string{
	"package.json":   {"bun.lock", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"},
	"pyproject.toml": {"uv.lock", "poetry.lock", "pdm.lock", "pylock.toml", "requirements.txt"},
	"Pipfile":        {"Pipfile.lock"},
	"Gemfile":        {"Gemfile.lock"},
	"Cargo.toml":     {"Cargo.lock"},
	"composer.json":  {"composer.lock"},
}

// Unreadable are lock formats OSV-Scanner cannot parse.
var Unreadable = map[string]string{
	"bun.lockb": "binary Bun lockfile; run `bun install --save-text-lockfile` to produce bun.lock",
}

// IgnoreFile is OSV-Scanner's per-folder configuration. Its ignore rules
// apply to the scan, so mamori always names it in the report.
const IgnoreFile = "osv-scanner.toml"

// Skipped directories hold installed copies of dependencies (or git's own
// data). They are not walked; the lockfile next to them is what is scanned.
// Every skipped folder is counted in the report.
var Skipped = map[string]bool{"node_modules": true, ".git": true, ".venv": true, "venv": true, "__pycache__": true}

// Candidate is a file found on disk that matters to the scan.
type Candidate struct {
	Rel  string // path relative to the scanned root, with forward slashes
	Kind string // lockfile | manifest | unreadable
}

// IsRequirements reports whether name is a pip requirements file.
func IsRequirements(name string) bool {
	return name == "requirements.txt" || (strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt"))
}

// Classify says what kind of file name is, or "".
func Classify(name string) string {
	switch {
	case Lockfiles[name] != "" || IsRequirements(name):
		return "lockfile"
	case Manifests[name] != nil:
		return "manifest"
	case Unreadable[name] != "":
		return "unreadable"
	case name == IgnoreFile:
		return "config"
	}
	return ""
}

// Walk lists the candidates under root and how many folders it skipped
// (see Skipped) or could not open.
func Walk(root string) (cands []Candidate, skipped int, unreadable []string, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path != root {
				rel, _ := filepath.Rel(root, path)
				unreadable = append(unreadable, filepath.ToSlash(rel))
				return nil
			}
			return err
		}
		if d.IsDir() {
			if path != root && Skipped[d.Name()] {
				skipped++
				return filepath.SkipDir
			}
			return nil
		}
		if k := Classify(d.Name()); k != "" {
			rel, _ := filepath.Rel(root, path)
			cands = append(cands, Candidate{Rel: filepath.ToSlash(rel), Kind: k})
		}
		return nil
	})
	return cands, skipped, unreadable, err
}

// Result is what one scanned root produced.
type Result struct {
	Files      []report.File
	Findings   []report.Finding
	BlindSpots []report.BlindSpot
	// Packages is every package seen, for the Patch the Planet package checks.
	Packages []Package
	// Ignores names the osv-scanner.toml files whose rules hid findings.
	Ignores []string
}

// Package is one resolved package from a lockfile.
type Package struct {
	Target, Ecosystem, Name, Version, Location string
}

// Dir scans the lockfiles under root. target names the scan in the report
// ("local:/path" or "github:owner/repo"); locate turns a path relative to
// root into what the reader sees.
func Dir(opts Options, target, root string, candidates []Candidate, locate func(rel string) string) (Result, error) {
	var res Result
	lockPaths := []string{}
	for _, c := range candidates {
		switch c.Kind {
		case "lockfile":
			lockPaths = append(lockPaths, filepath.Join(root, filepath.FromSlash(c.Rel)))
		case "unreadable":
			res.BlindSpots = append(res.BlindSpots, report.BlindSpot{Target: target, Path: locate(c.Rel), Code: "unreadable-format", Reason: Unreadable[filepath.Base(c.Rel)]})
		}
	}
	res.BlindSpots = append(res.BlindSpots, unpinnedManifests(target, candidates, locate)...)
	for _, c := range candidates {
		if c.Kind != "config" {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(c.Rel)))
		n := strings.Count(string(b), "[[IgnoredVulns]]") + strings.Count(string(b), "[[PackageOverrides]]")
		res.Ignores = append(res.Ignores, fmt.Sprintf("%s %s: %d ignore rule(s) from %s apply to this scan", target, locate(c.Rel), n, IgnoreFile))
	}
	if len(lockPaths) == 0 {
		return res, nil
	}

	actions := osvscanner.ScannerActions{
		LockfilePaths:         lockPaths,
		ShowAllPackages:       true,
		CompareOffline:        opts.Mode != Online,
		DownloadDatabases:     opts.Mode == Offline,
		LocalDBPath:           filepath.Join(opts.CacheDir, "osv"),
		PluginNetworkDisabled: true,
	}
	actions.TransitiveScanning.Disabled = true
	actions.HTTPClient = opts.HTTP
	actions.RequestUserAgent = "mamori"

	logs := &collector{inner: opts.Log, state: &collected{}}
	if logs.inner == nil {
		logs.inner = slog.DiscardHandler
	}
	osvscanner.SetLogger(logs)
	vr, err := osvscanner.DoScan(actions)
	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) && !errors.Is(err, osvscanner.ErrNoPackagesFound) {
		return res, fmt.Errorf("osv-scanner: %w", err)
	}

	seen := map[string]bool{}
	for _, src := range vr.Results {
		rel := relTo(root, src.Source.Path)
		seen[rel] = true
		f := report.File{Path: locate(rel), Packages: len(src.Packages)}
		for _, pv := range src.Packages {
			if f.Ecosystem == "" {
				f.Ecosystem = pv.Package.Ecosystem
			}
			res.Packages = append(res.Packages, Package{Target: target, Ecosystem: pv.Package.Ecosystem, Name: pv.Package.Name, Version: pv.Package.Version, Location: locate(rel)})
			res.Findings = append(res.Findings, findings(target, locate(rel), pv)...)
		}
		res.Files = append(res.Files, f)
	}
	for _, c := range candidates {
		if c.Kind == "lockfile" && seen[c.Rel] {
			if n := npmUnresolved(filepath.Join(root, filepath.FromSlash(c.Rel))); n > 0 {
				res.BlindSpots = append(res.BlindSpots, report.BlindSpot{Target: target, Path: locate(c.Rel), Code: "npm-unresolved",
					Reason: fmt.Sprintf("%d package(s) have no `resolved` registry URL; OSV-Scanner does not match them", n)})
			}
		}
		if c.Kind == "lockfile" && !seen[c.Rel] {
			res.BlindSpots = append(res.BlindSpots, report.BlindSpot{Target: target, Path: locate(c.Rel), Code: "not-parsed",
				Reason: "OSV-Scanner returned nothing for this file (empty, unsupported variant, or no packages)"})
		}
	}
	// OSV-Scanner logs a database it could not load and carries on with no
	// matches. Silence must not read as safety: check the databases are there
	// and turn logged errors into blind spots.
	if opts.Mode != Online {
		for _, f := range res.Files {
			if f.Ecosystem == "" {
				continue
			}
			db := filepath.Join(actions.LocalDBPath, "osv-scalibr", f.Ecosystem, "all.zip")
			if _, err := os.Stat(db); err != nil {
				res.BlindSpots = append(res.BlindSpots, report.BlindSpot{Target: target, Path: f.Path, Code: "no-db",
					Reason: "no " + f.Ecosystem + " vulnerability database on this machine"})
			}
		}
	}
	for _, m := range logs.state.errors() {
		res.BlindSpots = append(res.BlindSpots, report.BlindSpot{Target: target, Code: "scan-failed", Reason: m})
	}
	sort.Slice(res.Files, func(i, j int) bool { return res.Files[i].Path < res.Files[j].Path })
	return res, nil
}

// collector passes OSV-Scanner's log on and keeps its error messages.
type collector struct {
	inner slog.Handler
	state *collected
}

type collected struct {
	mu   sync.Mutex
	msgs []string
}

func (c *collected) add(m string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, x := range c.msgs {
		if x == m {
			return
		}
	}
	c.msgs = append(c.msgs, m)
}

func (c *collected) errors() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.msgs...)
}

func (c *collector) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= slog.LevelError || c.inner.Enabled(ctx, l)
}

func (c *collector) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		c.state.add(r.Message)
	}
	if c.inner.Enabled(ctx, r.Level) {
		return c.inner.Handle(ctx, r)
	}
	return nil
}

func (c *collector) WithAttrs(a []slog.Attr) slog.Handler {
	return &collector{inner: c.inner.WithAttrs(a), state: c.state}
}

func (c *collector) WithGroup(name string) slog.Handler {
	return &collector{inner: c.inner.WithGroup(name), state: c.state}
}

// npmUnresolved counts the packages in an npm lockfile that have no
// `resolved` URL. OSV-Scanner skips them when matching (they look like
// local or git dependencies), so they are a blind spot, not a pass.
// Workspace links and bundled packages are not counted.
func npmUnresolved(path string) int {
	switch filepath.Base(path) {
	case "package-lock.json", "npm-shrinkwrap.json":
	default:
		return 0
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var lock struct {
		Packages map[string]struct {
			Resolved string `json:"resolved"`
			Link     bool   `json:"link"`
			InBundle bool   `json:"inBundle"`
			Version  string `json:"version"`
		} `json:"packages"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return 0
	}
	n := 0
	for key, pkg := range lock.Packages {
		if key == "" || !strings.Contains(key, "node_modules/") || pkg.Link || pkg.InBundle || pkg.Version == "" {
			continue
		}
		if pkg.Resolved == "" {
			n++
		}
	}
	return n
}

func relTo(root, p string) string {
	if rel, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(p)
}

// unpinnedManifests flags manifests with no lockfile next to them.
func unpinnedManifests(target string, candidates []Candidate, locate func(string) string) []report.BlindSpot {
	present := map[string]bool{}
	for _, c := range candidates {
		present[c.Rel] = true
	}
	var out []report.BlindSpot
	for _, c := range candidates {
		if c.Kind != "manifest" {
			continue
		}
		dir := filepath.ToSlash(filepath.Dir(c.Rel))
		pinned := false
		for _, lock := range Manifests[filepath.Base(c.Rel)] {
			if present[joinRel(dir, lock)] {
				pinned = true
			}
		}
		if !pinned {
			out = append(out, report.BlindSpot{Target: target, Path: locate(c.Rel), Code: "no-lockfile",
				Reason: "dependencies are declared but no lockfile sits next to them, so the installed versions are unknown"})
		}
	}
	return out
}

func joinRel(dir, name string) string {
	if dir == "." || dir == "" {
		return name
	}
	return dir + "/" + name
}

// findings turns one package's OSV groups into report findings, one per group.
func findings(target, location string, pv models.PackageVulns) []report.Finding {
	byID := map[string]*osvschema.Vulnerability{}
	for _, v := range pv.Vulnerabilities {
		byID[v.GetId()] = v
	}
	var out []report.Finding
	for _, g := range pv.Groups {
		ids := uniq(append(append([]string{}, g.IDs...), g.Aliases...))
		f := report.Finding{
			Kind: "package", Target: target, Location: location,
			Ecosystem: pv.Package.Ecosystem, Package: pv.Package.Name, Version: pv.Package.Version,
			IDs: ids, Severity: "unknown",
		}
		if score, err := strconv.ParseFloat(g.MaxSeverity, 64); err == nil {
			f.Severity = report.SeverityFromScore(score)
		}
		for _, id := range g.IDs {
			v := byID[id]
			if v == nil {
				continue
			}
			if strings.HasPrefix(id, "MAL-") {
				f.Kind = "malicious"
				f.Severity = "critical"
			}
			if f.Summary == "" {
				f.Summary = v.GetSummary()
			}
			if s := dbSeverity(v); s != "" && f.Severity == "unknown" {
				f.Severity = s
			}
			f.Fixed = uniq(append(f.Fixed, fixedVersions(v, pv.Package.Name, pv.Package.Ecosystem)...))
		}
		out = append(out, f)
	}
	return out
}

// dbSeverity reads GitHub's label ("CRITICAL", "HIGH", "MODERATE", "LOW").
func dbSeverity(v *osvschema.Vulnerability) string {
	ds := v.GetDatabaseSpecific()
	if ds == nil {
		return ""
	}
	s, ok := ds.GetFields()["severity"]
	if !ok {
		return ""
	}
	switch strings.ToLower(s.GetStringValue()) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low":
		return "low"
	}
	return ""
}

func fixedVersions(v *osvschema.Vulnerability, name, ecosystem string) []string {
	var out []string
	for _, a := range v.GetAffected() {
		p := a.GetPackage()
		if p == nil || !strings.EqualFold(p.GetName(), name) || !strings.HasPrefix(ecosystem, strings.Split(p.GetEcosystem(), ":")[0]) {
			continue
		}
		for _, r := range a.GetRanges() {
			for _, e := range r.GetEvents() {
				if e.GetFixed() != "" {
					out = append(out, e.GetFixed())
				}
			}
		}
	}
	return out
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// CacheDir is mamori's per-user cache folder.
func CacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "mamori"), nil
}

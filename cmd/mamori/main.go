// Command mamori scans lockfiles, GitHub repositories (read-only) and this
// machine's runtimes for known vulnerabilities, and lists what it scanned,
// what it found, and what it could not read.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/jun-omise/mamori/internal/egress"
	"github.com/jun-omise/mamori/internal/ghread"
	"github.com/jun-omise/mamori/internal/kev"
	"github.com/jun-omise/mamori/internal/report"
	"github.com/jun-omise/mamori/internal/runtimes"
	"github.com/jun-omise/mamori/internal/scan"
	"github.com/jun-omise/mamori/internal/version"
	"github.com/jun-omise/mamori/overlay"
)

// Version is set at release time with -ldflags "-X main.Version=...".
var Version = "dev"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usage = `mamori — read-only vulnerability scan for your code and this machine

Usage:
  mamori scan [targets] [flags]   scan and report
  mamori egress                   list every host mamori may contact, and why
  mamori version

Targets (any number; with none, scans the current folder and this machine's runtimes):
  --local PATH        a folder with lockfiles (repeatable)
  --github OWNER      every repository of a user or organization (repeatable)
  --github OWNER/REPO one repository (repeatable)
  --runtimes          Node.js, Bun, Python, PHP, Envoy and Istio installed here

Matching:
  (default)           download the public OSV database when it changed, match on this machine;
                      your package list is never sent anywhere
  --online            ask the OSV API instead (sends package names and versions to api.osv.dev)
  --offline           no network at all; uses the cached database

Output:
  --format text|json|markdown   (default text)
  --out FILE                    write the report to FILE
  --lang ja|en                  (default from the system language)

GitHub token (read-only is enough): MAMORI_GITHUB_TOKEN, GITHUB_TOKEN, GH_TOKEN, or "gh auth token".
Exit codes: 0 clean, 1 findings, 2 error, 3 no findings but blind spots.
`

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:], stdout, stderr)
	case "egress":
		for _, r := range egress.Rules {
			only := ""
			if r.OnlineOnly {
				only = "  [--online only]"
			}
			fmt.Fprintf(stdout, "%-45s %-14s %s%s\n", r.Host, strings.Join(r.Methods, ","), r.Purpose, only)
		}
		return 0
	case "version", "--version":
		fmt.Fprintln(stdout, "mamori", Version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 2
}

func defaultLang() string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			if strings.HasPrefix(strings.ToLower(v), "ja") {
				return "ja"
			}
			return "en"
		}
	}
	return "en"
}

type scanFlags struct {
	local, github                 multi
	runtimes, online, offline     bool
	format, out, lang, cacheDir   string
	includeForks, includeArchived bool
	verbose                       bool
}

func cmdScan(args []string, stdout, stderr io.Writer) int {
	var f scanFlags
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Var(&f.local, "local", "folder to scan (repeatable)")
	fs.Var(&f.github, "github", "OWNER or OWNER/REPO to scan read-only (repeatable)")
	fs.BoolVar(&f.runtimes, "runtimes", false, "check runtimes installed on this machine")
	fs.BoolVar(&f.online, "online", false, "match with the OSV API (sends package names and versions)")
	fs.BoolVar(&f.offline, "offline", false, "no network; use cached databases only")
	fs.StringVar(&f.format, "format", "text", "text, json or markdown")
	fs.StringVar(&f.out, "out", "", "write the report to this file")
	fs.StringVar(&f.lang, "lang", defaultLang(), "ja or en")
	fs.StringVar(&f.cacheDir, "cache-dir", "", "where databases are kept (default: the user cache folder)")
	fs.BoolVar(&f.includeForks, "include-forks", false, "also scan forks")
	fs.BoolVar(&f.includeArchived, "include-archived", false, "also scan archived repositories")
	fs.BoolVar(&f.verbose, "verbose", false, "show OSV-Scanner's own log")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if f.online && f.offline {
		fmt.Fprintln(stderr, "--online and --offline cannot be used together")
		return 2
	}
	if len(f.local) == 0 && len(f.github) == 0 && !f.runtimes {
		f.local = multi{"."}
		f.runtimes = true
	}
	if f.offline && len(f.github) > 0 {
		fmt.Fprintln(stderr, "--github needs the network; it cannot be combined with --offline")
		return 2
	}
	if !f.verbose {
		log.SetOutput(io.Discard)
	}
	if f.cacheDir == "" {
		dir, err := scan.CacheDir()
		if err != nil {
			fmt.Fprintln(stderr, "cannot find a cache folder:", err)
			return 2
		}
		f.cacheDir = dir
	}

	rep, err := scanAll(f, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "mamori:", err)
		return 2
	}

	w := stdout
	if f.out != "" {
		file, err := os.Create(f.out)
		if err != nil {
			fmt.Fprintln(stderr, "mamori:", err)
			return 2
		}
		defer file.Close()
		w = file
	}
	lang := report.Lang(f.lang)
	switch f.format {
	case "json":
		if err := report.JSON(w, rep); err != nil {
			fmt.Fprintln(stderr, "mamori:", err)
			return 2
		}
	case "markdown", "md":
		report.Markdown(w, rep, lang)
	default:
		report.Text(w, rep, lang)
	}
	return rep.ExitCode()
}

func scanAll(f scanFlags, stderr io.Writer) (*report.Report, error) {
	rec := egress.NewRecorder()
	client := egress.NewClient(egress.Policy{Offline: f.offline, Online: f.online}, rec)
	mode := scan.Offline
	switch {
	case f.offline:
		mode = scan.StrictOffline
	case f.online:
		mode = scan.Online
	}
	opts := scan.Options{Mode: mode, CacheDir: f.cacheDir, HTTP: client}
	if f.verbose {
		opts.Log = slog.NewTextHandler(stderr, nil)
	}
	rep := &report.Report{Tool: "mamori", Version: Version, Started: time.Now(), Mode: string(mode)}
	progress := func(format string, a ...any) { fmt.Fprintf(stderr, format+"\n", a...) }

	var netClient *http.Client
	if !f.offline {
		netClient = client
	}
	data, fromRemote, err := overlay.Load(netClient)
	if err != nil {
		return nil, err
	}
	if !fromRemote {
		rep.Notes = append(rep.Notes, fmt.Sprintf("Patch the Planet data: built-in copy reviewed %s", data.Reviewed))
	} else {
		rep.Notes = append(rep.Notes, fmt.Sprintf("Patch the Planet data: published copy reviewed %s", data.Reviewed))
	}
	catalog, stale, err := kev.Load(netClient, f.cacheDir)
	if err != nil {
		rep.BlindSpots = append(rep.BlindSpots, report.BlindSpot{Target: "CISA KEV", Code: "kev-missing", Reason: err.Error()})
	} else if stale {
		rep.Notes = append(rep.Notes, "CISA KEV catalog is older than a day (offline)")
	}

	var packages []scan.Package
	for _, dir := range f.local {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		progress("mamori: scanning %s", abs)
		target := "local:" + abs
		cands, skipped, unreadable, err := scan.Walk(abs)
		if err != nil {
			return nil, err
		}
		if skipped > 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s: %d folder(s) of installed copies (node_modules, .venv, venv, __pycache__, .git) were not walked; the lockfiles next to them were scanned", target, skipped))
		}
		for _, u := range unreadable {
			rep.BlindSpots = append(rep.BlindSpots, report.BlindSpot{Target: target, Path: u, Code: "fetch-failed", Reason: "could not be opened"})
		}
		res, err := scan.Dir(opts, target, abs, cands, func(rel string) string { return rel })
		tg := report.Target{Kind: "local", Name: abs, Files: res.Files}
		rep.Targets = append(rep.Targets, tg)
		addResult(rep, res, err, target)
		packages = append(packages, res.Packages...)
	}

	if len(f.github) > 0 {
		pk, err := scanGitHub(f, opts, client, rep, progress)
		if err != nil {
			return nil, err
		}
		packages = append(packages, pk...)
	}

	checked := map[string][]string{}
	if f.runtimes {
		progress("mamori: checking runtimes on this machine")
		found := runtimes.Detect()
		tg := report.Target{Kind: "runtimes", Name: "this machine"}
		for _, r := range found {
			tg.Runtimes = append(tg.Runtimes, report.Runtime{Name: r.Name, Version: r.Version, Path: r.Path})
			for k, v := range r.Packages {
				tg.Runtimes = append(tg.Runtimes, report.Runtime{Name: "python:" + k, Version: v, Path: r.Path})
			}
		}
		rep.Targets = append(rep.Targets, tg)
		fs, c := runtimes.Check(found, data)
		rep.Findings = append(rep.Findings, fs...)
		checked = c
		if !f.offline {
			if nf, err := runtimes.NodeReleases(client, found); err == nil {
				rep.Findings = append(rep.Findings, nf...)
			} else {
				rep.Notes = append(rep.Notes, "Node.js release list could not be read: "+err.Error())
			}
		}
	}

	checkOverlayPackages(rep, data, packages, checked)
	for i := range rep.Findings {
		if catalog != nil && catalog.Exploited(rep.Findings[i].IDs) {
			rep.Findings[i].KEV = true
		}
	}
	summarizeDisclosures(rep, data, checked)
	rep.Sort()
	rep.Egress = rec.Contacted()
	rep.Finished = time.Now()
	return rep, nil
}

func addResult(rep *report.Report, res scan.Result, err error, target string) {
	rep.Notes = append(rep.Notes, res.Ignores...)
	rep.Findings = append(rep.Findings, res.Findings...)
	rep.BlindSpots = append(rep.BlindSpots, res.BlindSpots...)
	if err != nil {
		code := "scan-failed"
		if strings.Contains(err.Error(), "local") && strings.Contains(strings.ToLower(err.Error()), "db") {
			code = "no-db"
		}
		rep.BlindSpots = append(rep.BlindSpots, report.BlindSpot{Target: target, Code: code, Reason: err.Error()})
	}
}

func scanGitHub(f scanFlags, opts scan.Options, client *http.Client, rep *report.Report, progress func(string, ...any)) ([]scan.Package, error) {
	token, source := ghread.TokenFromEnv()
	gh := &ghread.Client{HTTP: client, Token: token}
	me, err := gh.Whoami()
	switch {
	case err != nil:
		return nil, fmt.Errorf("GitHub token from %s was rejected: %w", source, err)
	case token == "":
		rep.Notes = append(rep.Notes, "no GitHub token: only public repositories can be read, at 60 requests per hour")
	case len(me.WriteScopes()) > 0:
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"the GitHub token (%s) also allows writing (%s). mamori only sends GET requests, but a fine-grained token with read-only Contents and Metadata is enough and safer",
			source, strings.Join(me.WriteScopes(), ", ")))
	case strings.HasPrefix(token, "github_pat_"):
		rep.Notes = append(rep.Notes, "fine-grained GitHub token: mamori needs only read access to Contents and Metadata (and Dependabot alerts, optionally)")
	}

	var repos []ghread.Repo
	for _, spec := range f.github {
		if strings.Contains(spec, "/") {
			r, err := gh.Repo(spec)
			if err != nil {
				rep.BlindSpots = append(rep.BlindSpots, report.BlindSpot{Target: "github:" + spec, Code: "repo-failed", Reason: err.Error()})
				continue
			}
			repos = append(repos, r)
			continue
		}
		list, err := gh.Repos(spec, me)
		if err != nil {
			rep.BlindSpots = append(rep.BlindSpots, report.BlindSpot{Target: "github:" + spec, Code: "repo-failed", Reason: err.Error()})
			continue
		}
		skipped := 0
		for _, r := range list {
			if (r.Fork && !f.includeForks) || (r.Archived && !f.includeArchived) {
				skipped++
				continue
			}
			repos = append(repos, r)
		}
		if skipped > 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("github:%s — %d forks/archived repositories skipped (use --include-forks / --include-archived)", spec, skipped))
		}
	}

	var packages []scan.Package
	for _, r := range repos {
		progress("mamori: reading github:%s", r.FullName)
		pk := scanRepo(gh, opts, r, rep)
		packages = append(packages, pk...)
		time.Sleep(ghread.Pause)
	}
	return packages, nil
}

func scanRepo(gh *ghread.Client, opts scan.Options, r ghread.Repo, rep *report.Report) []scan.Package {
	target := "github:" + r.FullName
	tg := report.Target{Kind: "github", Name: r.FullName, Facts: map[string]string{}}
	defer func() { rep.Targets = append(rep.Targets, tg) }()
	if r.DefaultBranch == "" {
		rep.BlindSpots = append(rep.BlindSpots, report.BlindSpot{Target: target, Code: "repo-failed", Reason: "empty repository"})
		return nil
	}
	entries, truncated, err := gh.Tree(r)
	if err != nil {
		rep.BlindSpots = append(rep.BlindSpots, report.BlindSpot{Target: target, Code: "repo-failed", Reason: err.Error()})
		return nil
	}
	if truncated {
		rep.BlindSpots = append(rep.BlindSpots, report.BlindSpot{Target: target, Code: "tree-truncated"})
	}
	dir, err := os.MkdirTemp("", "mamori-")
	if err != nil {
		rep.BlindSpots = append(rep.BlindSpots, report.BlindSpot{Target: target, Code: "repo-failed", Reason: err.Error()})
		return nil
	}
	defer os.RemoveAll(dir)

	var cands []scan.Candidate
	skipped := 0
	for _, e := range entries {
		if e.Type == "commit" {
			rep.BlindSpots = append(rep.BlindSpots, report.BlindSpot{Target: target, Path: e.Path, Code: "submodule",
				Reason: "git submodule; scan its repository separately"})
			continue
		}
		if e.Type != "blob" {
			continue
		}
		if skippedPath(e.Path) {
			if scan.Classify(path.Base(e.Path)) != "" {
				skipped++
			}
			continue
		}
		kind := scan.Classify(path.Base(e.Path))
		if kind == "" {
			continue
		}
		c := scan.Candidate{Rel: e.Path, Kind: kind}
		if kind == "lockfile" || kind == "config" {
			b, err := gh.File(r, e.Path)
			if err != nil {
				rep.BlindSpots = append(rep.BlindSpots, report.BlindSpot{Target: target, Path: e.Path, Code: "fetch-failed", Reason: err.Error()})
				continue
			}
			dst := filepath.Join(dir, filepath.FromSlash(e.Path))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err == nil {
				err = os.WriteFile(dst, b, 0o644)
			}
			if err != nil {
				rep.BlindSpots = append(rep.BlindSpots, report.BlindSpot{Target: target, Path: e.Path, Code: "fetch-failed", Reason: err.Error()})
				continue
			}
		}
		cands = append(cands, c)
	}
	if skipped > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%s: %d lockfile(s) committed inside node_modules/.venv/venv were not scanned (installed copies)", target, skipped))
	}
	res, err := scan.Dir(opts, target, dir, cands, func(rel string) string { return rel })
	tg.Files = res.Files
	addResult(rep, res, err, target)

	if n, err := gh.DependabotOpen(r); err == nil {
		tg.Facts["Dependabot open alerts"] = n
	} else if !errors.Is(err, ghread.ErrNotFound) {
		tg.Facts["Dependabot"] = err.Error()
	}
	if total, ranges, err := gh.GraphCoverage(r); err == nil && total > 0 {
		tg.Facts["GitHub dependency graph"] = fmt.Sprintf("%d packages, %d without a resolved version", total, ranges)
		if len(res.Files) > 0 && ranges*2 > total {
			rep.BlindSpots = append(rep.BlindSpots, report.BlindSpot{Target: target, Code: "graph-blind",
				Reason: "GitHub's dependency graph lists versions as ranges"})
		}
	}
	return res.Packages
}

func skippedPath(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if scan.Skipped[seg] {
			return true
		}
	}
	return false
}

// checkOverlayPackages checks lockfile packages that a Patch the Planet
// disclosure names (e.g. the Python Brotli binding), unless OSV already
// reported the same CVE for that package.
func checkOverlayPackages(rep *report.Report, data overlay.Data, packages []scan.Package, checked map[string][]string) {
	reported := map[string]bool{}
	for _, f := range rep.Findings {
		for _, id := range f.IDs {
			reported[f.Target+"|"+strings.ToLower(f.Package)+"|"+f.Location+"|"+id] = true
		}
	}
	for _, d := range data.Disclosures {
		for _, p := range d.Products {
			if p.Package == nil {
				continue
			}
			for _, pkg := range packages {
				if pkg.Ecosystem != p.Package.Ecosystem || !strings.EqualFold(normalize(pkg.Name), normalize(p.Package.Name)) {
					continue
				}
				checked[d.ID] = appendOnce(checked[d.ID], p.Name)
				already := false
				for _, cve := range d.CVEs {
					if reported[pkg.Target+"|"+strings.ToLower(pkg.Name)+"|"+pkg.Location+"|"+cve] {
						already = true
					}
				}
				status, fix := version.Against(pkg.Version, p.Fixed, p.Branch)
				if already || status == version.Fixed || status == version.Unknown {
					continue
				}
				fixed := []string{fix}
				if status == version.NoFixInLine {
					fixed = p.Fixed
				}
				rep.Findings = append(rep.Findings, report.Finding{
					Kind: "package", Target: pkg.Target, Location: pkg.Location,
					Ecosystem: pkg.Ecosystem, Package: pkg.Name, Version: pkg.Version, IDs: d.CVEs, Severity: "critical",
					Summary: d.Title + ": " + d.Summary, Fixed: fixed, PatchThePlanet: d.ID, Advice: d.Mitigation,
				})
			}
		}
	}
}

func normalize(s string) string {
	return strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(s))
}

func appendOnce(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func summarizeDisclosures(rep *report.Report, data overlay.Data, checked map[string][]string) {
	for _, d := range data.Disclosures {
		s := report.Disclosure{ID: d.ID, Title: d.Title, CVEs: d.CVEs, URL: d.URL, Checked: checked[d.ID]}
		done := map[string]bool{}
		for _, c := range s.Checked {
			done[c] = true
		}
		for _, p := range d.Products {
			if !done[p.Name] {
				s.Manual = append(s.Manual, p.Name)
			}
		}
		for _, f := range rep.Findings {
			if f.PatchThePlanet == d.ID {
				s.Affected++
			}
		}
		rep.Disclosure = append(rep.Disclosure, s)
	}
}

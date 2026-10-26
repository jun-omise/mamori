// Package runtimes finds the language runtimes installed on this machine and
// checks them against the Patch the Planet data and, when the network is
// allowed, the Node.js release list.
//
// It runs each runtime only to ask its version ("node --version"); Python is
// started isolated (-I) and only reads installed package metadata.
package runtimes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/jun-omise/mamori/internal/report"
	"github.com/jun-omise/mamori/internal/version"
	"github.com/jun-omise/mamori/overlay"
)

// Found is one runtime binary and the version it reported.
type Found struct {
	Name    string // node | bun | php | envoy | istio | python
	Version string
	Path    string
	// Packages holds Python package versions (Brotli, brotlicffi) for python.
	Packages map[string]string
}

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func glob(patterns ...string) []string {
	var out []string
	for _, p := range patterns {
		m, _ := filepath.Glob(p)
		out = append(out, m...)
	}
	return out
}

// candidates lists where each runtime may live besides PATH.
func candidates(name string) []string {
	home, _ := os.UserHomeDir()
	var paths []string
	if p, err := exec.LookPath(exe(name)); err == nil {
		paths = append(paths, p)
	}
	switch name {
	case "node":
		nvm := os.Getenv("NVM_DIR")
		if nvm == "" {
			nvm = filepath.Join(home, ".nvm")
		}
		paths = append(paths, glob(
			filepath.Join(nvm, "versions", "node", "*", "bin", "node"),
			filepath.Join(home, ".volta", "tools", "image", "node", "*", "bin", "node"),
			filepath.Join(home, ".local", "share", "fnm", "node-versions", "*", "installation", "bin", "node"),
			filepath.Join(home, "Library", "Application Support", "fnm", "node-versions", "*", "installation", "bin", "node"),
		)...)
		if runtime.GOOS == "windows" {
			for _, root := range []string{os.Getenv("NVM_HOME"), filepath.Join(os.Getenv("APPDATA"), "nvm")} {
				if root != "" {
					paths = append(paths, glob(filepath.Join(root, "v*", "node.exe"))...)
				}
			}
			paths = append(paths, glob(
				filepath.Join(os.Getenv("LOCALAPPDATA"), "Volta", "tools", "image", "node", "*", "node.exe"),
				filepath.Join(os.Getenv("APPDATA"), "fnm", "node-versions", "*", "installation", "node.exe"),
			)...)
		}
	case "bun":
		paths = append(paths, filepath.Join(home, ".bun", "bin", exe("bun")))
	case "python":
		for _, alt := range []string{"python3", "py"} {
			if p, err := exec.LookPath(exe(alt)); err == nil {
				paths = append(paths, p)
			}
		}
	}
	// Resolve symlinks so one binary reached two ways is listed once.
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			real = p
		}
		if !seen[real] {
			seen[real] = true
			out = append(out, real)
		}
	}
	return out
}

func run(path string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

const pyProbe = `import importlib.metadata as m, platform
print(platform.python_version())
for d in ("Brotli", "brotlicffi"):
    try: print(d, m.version(d))
    except Exception: pass`

// Detect finds the runtimes on this machine.
func Detect() []Found {
	var found []Found
	versionArgs := map[string][]string{
		"node": {"--version"}, "bun": {"--version"}, "php": {"-v"}, "envoy": {"--version"},
		"istioctl": {"version", "--remote=false", "--short"},
	}
	for _, name := range []string{"node", "bun", "php", "envoy", "istioctl"} {
		for _, p := range candidates(name) {
			out, err := run(p, versionArgs[name]...)
			v, ok := version.Parse(firstLine(out))
			if err != nil || !ok {
				continue
			}
			n := name
			if n == "istioctl" {
				n = "istio"
			}
			found = append(found, Found{Name: n, Version: v.Raw, Path: p})
		}
	}
	for _, p := range candidates("python") {
		out, err := run(p, "-I", "-c", pyProbe)
		if err != nil {
			continue
		}
		lines := strings.Split(out, "\n")
		f := Found{Name: "python", Version: strings.TrimSpace(lines[0]), Path: p, Packages: map[string]string{}}
		for _, l := range lines[1:] {
			if k, v, ok := strings.Cut(strings.TrimSpace(l), " "); ok {
				f.Packages[k] = v
			}
		}
		found = append(found, f)
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].Name < found[j].Name })
	return found
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// Check compares the runtimes with the Patch the Planet data. It returns the
// findings and, for the disclosure summary, which products were checked.
func Check(found []Found, data overlay.Data) (findings []report.Finding, checked map[string][]string) {
	checked = map[string][]string{}
	for _, d := range data.Disclosures {
		for _, p := range d.Products {
			for _, f := range found {
				var installed, what string
				switch {
				case p.Runtime != "" && p.Runtime == f.Name:
					installed, what = f.Version, p.Name
				case p.Package != nil && p.Package.Ecosystem == "PyPI" && f.Name == "python" && f.Packages[p.Package.Name] != "":
					installed, what = f.Packages[p.Package.Name], p.Package.Name
				default:
					continue
				}
				checked[d.ID] = appendOnce(checked[d.ID], p.Name)
				status, fix := version.Against(installed, p.Fixed, p.Branch)
				if status == version.Fixed || status == version.Unknown {
					continue
				}
				fixed := []string{fix}
				advice := fmt.Sprintf("update to %s or later", fix)
				if status == version.NoFixInLine {
					fixed = p.Fixed
					advice = "this release line has no fixed release; move to a supported line (" + strings.Join(p.Fixed, ", ") + ")"
				}
				if p.Note != "" {
					advice += ". " + p.Note
				}
				findings = append(findings, report.Finding{
					Kind: "runtime", Target: "runtimes", Location: f.Path,
					Package: what, Version: installed, IDs: d.CVEs, Severity: "critical",
					Summary: d.Title + ": " + d.Summary, Fixed: fixed, PatchThePlanet: d.ID, Advice: advice,
				})
			}
		}
	}
	return findings, checked
}

func appendOnce(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// NodeReleases checks each Node.js against nodejs.org's release list: a
// security release newer than the installed one in the same line, or a line
// past its end of life. It needs the network (nodejs.org, endoflife.date).
func NodeReleases(client *http.Client, found []Found) ([]report.Finding, error) {
	var index []struct {
		Version  string `json:"version"`
		Security bool   `json:"security"`
	}
	if err := getJSON(client, "https://nodejs.org/dist/index.json", &index); err != nil {
		return nil, err
	}
	var cycles []struct {
		Cycle string `json:"cycle"`
		EOL   any    `json:"eol"`
	}
	eol := map[string]string{}
	if err := getJSON(client, "https://endoflife.date/api/nodejs.json", &cycles); err == nil {
		for _, c := range cycles {
			if s, ok := c.EOL.(string); ok {
				eol[c.Cycle] = s
			}
		}
	}
	today := time.Now().UTC().Format("2006-01-02")
	var out []report.Finding
	for _, f := range found {
		if f.Name != "node" {
			continue
		}
		v, ok := version.Parse(f.Version)
		if !ok {
			continue
		}
		line := version.Branch(v, "major")
		var missed []string
		latest := ""
		for _, r := range index {
			rv, ok := version.Parse(r.Version)
			if !ok || version.Branch(rv, "major") != line {
				continue
			}
			if latest == "" {
				latest = rv.Raw
			}
			if r.Security && version.Compare(rv, v) > 0 {
				missed = append(missed, rv.Raw)
			}
		}
		if len(missed) > 0 {
			out = append(out, report.Finding{
				Kind: "runtime", Target: "runtimes", Location: f.Path, Package: "Node.js", Version: f.Version,
				IDs: []string{"nodejs-security-release"}, Severity: "high",
				Summary: fmt.Sprintf("%d Node.js security release(s) in the v%s line are newer than this one", len(missed), line),
				Fixed:   []string{latest}, Advice: "update to " + latest,
			})
		}
		if d := eol[line]; d != "" && d <= today {
			out = append(out, report.Finding{
				Kind: "runtime", Target: "runtimes", Location: f.Path, Package: "Node.js", Version: f.Version,
				IDs: []string{"nodejs-end-of-life"}, Severity: "high",
				Summary: fmt.Sprintf("the v%s line reached end of life on %s and gets no more security fixes", line, d),
				Advice:  "move to a supported line",
			})
		}
	}
	return out, nil
}

func getJSON(client *http.Client, u string, v any) error {
	resp, err := client.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(v)
}

// Package ghread reads GitHub repositories without cloning and without any
// write access: it lists repositories, reads their file trees, downloads the
// lockfiles, and reads Dependabot and dependency-graph status.
//
// Every request is a GET through the egress guard, which refuses anything
// else for api.github.com. A token that could write is still only used to read.
package ghread

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// MaxFileBytes caps a single downloaded file.
const MaxFileBytes = 64 << 20

// Client reads GitHub.
type Client struct {
	HTTP  *http.Client
	Token string
	Base  string // https://api.github.com unless testing
}

// Repo is one repository to scan.
type Repo struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Fork          bool   `json:"fork"`
	Archived      bool   `json:"archived"`
}

// Entry is one file in a repository tree.
type Entry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

// ErrNotFound is returned for 404s (missing repo, or no access).
var ErrNotFound = errors.New("not found or no access")

// TokenFromEnv finds a token: MAMORI_GITHUB_TOKEN, GITHUB_TOKEN, GH_TOKEN,
// then `gh auth token`. source says where it came from ("" when none).
func TokenFromEnv() (token, source string) {
	for _, k := range []string{"MAMORI_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v, k
		}
	}
	if gh, err := exec.LookPath("gh"); err == nil {
		out, err := exec.Command(gh, "auth", "token").Output()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			return strings.TrimSpace(string(out)), "gh auth token"
		}
	}
	return "", ""
}

func (c *Client) base() string {
	if c.Base != "" {
		return strings.TrimRight(c.Base, "/")
	}
	return "https://api.github.com"
}

func (c *Client) get(path, accept string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.base()+path, nil)
	if err != nil {
		return nil, err
	}
	if accept == "" {
		accept = "application/vnd.github+json"
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "mamori")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0":
		reset := resp.Header.Get("X-RateLimit-Reset")
		return nil, fmt.Errorf("GitHub rate limit reached (resets at unix %s); set a token to raise it", reset)
	}
	return nil, fmt.Errorf("GitHub %s: %s", resp.Status, githubMessage(body))
}

func githubMessage(body []byte) string {
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &m) == nil && m.Message != "" {
		return m.Message
	}
	return strings.TrimSpace(string(body))
}

func (c *Client) getJSON(path string, v any) (http.Header, error) {
	resp, err := c.get(path, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return resp.Header, json.NewDecoder(resp.Body).Decode(v)
}

// Identity is who the token belongs to and what it could do.
type Identity struct {
	Login string
	// Scopes is the X-OAuth-Scopes header of a classic token; empty for
	// fine-grained tokens, whose permissions GitHub does not report.
	Scopes string
}

// WriteScopes lists the scopes of a classic token that allow writing.
func (i Identity) WriteScopes() []string {
	var out []string
	for _, s := range strings.Split(i.Scopes, ",") {
		s = strings.TrimSpace(s)
		switch {
		case s == "repo", s == "public_repo", s == "workflow", s == "delete_repo", s == "gist",
			strings.HasPrefix(s, "write:"), strings.HasPrefix(s, "admin:"):
			out = append(out, s)
		}
	}
	return out
}

// Whoami reads the token's user. It returns an empty Identity without a token.
func (c *Client) Whoami() (Identity, error) {
	if c.Token == "" {
		return Identity{}, nil
	}
	var u struct {
		Login string `json:"login"`
	}
	h, err := c.getJSON("/user", &u)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Login: u.Login, Scopes: h.Get("X-OAuth-Scopes")}, nil
}

// Repos lists an owner's repositories. For the token's own login it uses
// /user/repos so private repositories are included.
func (c *Client) Repos(owner string, me Identity) ([]Repo, error) {
	var paths []string
	switch {
	case me.Login != "" && strings.EqualFold(owner, me.Login):
		paths = []string{"/user/repos?affiliation=owner&per_page=100"}
	default:
		paths = []string{"/orgs/" + url.PathEscape(owner) + "/repos?type=all&per_page=100", "/users/" + url.PathEscape(owner) + "/repos?per_page=100"}
	}
	var lastErr error
	for _, p := range paths {
		repos, err := c.paginate(p)
		if err == nil {
			return repos, nil
		}
		lastErr = err
		if !errors.Is(err, ErrNotFound) {
			break
		}
	}
	return nil, lastErr
}

func (c *Client) paginate(first string) ([]Repo, error) {
	var all []Repo
	path := first
	for page := 0; path != "" && page < 50; page++ {
		var batch []Repo
		h, err := c.getJSON(path, &batch)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		path = nextLink(h.Get("Link"), c.base())
	}
	return all, nil
}

func nextLink(link, base string) string {
	for _, part := range strings.Split(link, ",") {
		segs := strings.Split(part, ";")
		if len(segs) < 2 || !strings.Contains(segs[1], `rel="next"`) {
			continue
		}
		u := strings.Trim(strings.TrimSpace(segs[0]), "<>")
		return strings.TrimPrefix(u, base)
	}
	return ""
}

// Repo reads one repository.
func (c *Client) Repo(fullName string) (Repo, error) {
	var r Repo
	_, err := c.getJSON("/repos/"+fullName, &r)
	return r, err
}

// Tree lists the files on the default branch. truncated is true when GitHub
// cut the listing short (very large repositories).
func (c *Client) Tree(r Repo) (entries []Entry, truncated bool, err error) {
	var t struct {
		Tree      []Entry `json:"tree"`
		Truncated bool    `json:"truncated"`
	}
	_, err = c.getJSON("/repos/"+r.FullName+"/git/trees/"+url.PathEscape(r.DefaultBranch)+"?recursive=1", &t)
	return t.Tree, t.Truncated, err
}

// File downloads one file from the default branch.
func (c *Client) File(r Repo, path string) ([]byte, error) {
	escaped := make([]string, 0)
	for _, seg := range strings.Split(path, "/") {
		escaped = append(escaped, url.PathEscape(seg))
	}
	resp, err := c.get("/repos/"+r.FullName+"/contents/"+strings.Join(escaped, "/")+"?ref="+url.QueryEscape(r.DefaultBranch), "application/vnd.github.raw")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("file larger than %d MB", MaxFileBytes>>20)
	}
	return b, nil
}

// DependabotOpen returns how many open Dependabot alerts GitHub reports
// ("100+" when there are more than fit in one page), or an explanation when
// it cannot be read (alerts disabled, or the token lacks permission).
func (c *Client) DependabotOpen(r Repo) (string, error) {
	var alerts []json.RawMessage
	h, err := c.getJSON("/repos/"+r.FullName+"/dependabot/alerts?state=open&per_page=100", &alerts)
	if err != nil {
		return "", err
	}
	if strings.Contains(h.Get("Link"), `rel="next"`) {
		return "100+", nil
	}
	return fmt.Sprint(len(alerts)), nil
}

// GraphCoverage reads GitHub's dependency graph (SBOM) and counts packages
// whose version is a range rather than a resolved version. A high share of
// ranges means GitHub did not read the lockfile, so Dependabot's silence
// says little.
func (c *Client) GraphCoverage(r Repo) (total, ranges int, err error) {
	var s struct {
		SBOM struct {
			Packages []struct {
				Name        string `json:"name"`
				VersionInfo string `json:"versionInfo"`
			} `json:"packages"`
		} `json:"sbom"`
	}
	if _, err = c.getJSON("/repos/"+r.FullName+"/dependency-graph/sbom", &s); err != nil {
		return 0, 0, err
	}
	for _, p := range s.SBOM.Packages {
		if strings.HasPrefix(p.Name, "com.github.") { // the repository itself
			continue
		}
		total++
		if strings.ContainsAny(p.VersionInfo, "^~<>=*| ") {
			ranges++
		}
	}
	return total, ranges, nil
}

// Pause is a small delay between repositories to stay polite to the API.
var Pause = 150 * time.Millisecond

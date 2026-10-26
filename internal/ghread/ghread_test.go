package ghread

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeGitHub(t *testing.T, methods *[]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "repo, read:org")
		w.Write([]byte(`{"login":"alice"}`))
	})
	mux.HandleFunc("/user/repos", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "" {
			w.Header().Set("Link", `<`+"http://"+r.Host+`/user/repos?affiliation=owner&per_page=100&page=2>; rel="next"`)
			w.Write([]byte(`[{"full_name":"alice/a","default_branch":"main"}]`))
			return
		}
		w.Write([]byte(`[{"full_name":"alice/b","default_branch":"dev","fork":true}]`))
	})
	mux.HandleFunc("/repos/alice/a/git/trees/main", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"truncated":true,"tree":[{"path":"web/bun.lock","type":"blob"},{"path":"web/package.json","type":"blob"}]}`))
	})
	mux.HandleFunc("/repos/alice/a/contents/web/bun.lock", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github.raw" || r.URL.Query().Get("ref") != "main" {
			t.Errorf("raw download: accept=%q ref=%q", r.Header.Get("Accept"), r.URL.Query().Get("ref"))
		}
		w.Write([]byte("lock-bytes"))
	})
	mux.HandleFunc("/repos/alice/a/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"sbom":{"packages":[{"name":"com.github.alice/a","versionInfo":"main"},{"name":"npm:react","versionInfo":"^19.2.0"},{"name":"npm:zod","versionInfo":"3.25.76"}]}}`))
	})
	mux.HandleFunc("/repos/alice/a/dependabot/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"Dependabot alerts are disabled for this repository."}`))
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*methods = append(*methods, r.Method)
		mux.ServeHTTP(w, r)
	}))
}

func TestReadsWithoutWriting(t *testing.T) {
	var methods []string
	srv := fakeGitHub(t, &methods)
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), Token: "t", Base: srv.URL}

	me, err := c.Whoami()
	if err != nil || me.Login != "alice" {
		t.Fatalf("whoami: %+v %v", me, err)
	}
	if ws := me.WriteScopes(); len(ws) != 1 || ws[0] != "repo" {
		t.Errorf("write scopes = %v, want [repo]", ws)
	}
	repos, err := c.Repos("alice", me)
	if err != nil || len(repos) != 2 || repos[1].FullName != "alice/b" {
		t.Fatalf("repos (two pages): %+v %v", repos, err)
	}
	entries, truncated, err := c.Tree(repos[0])
	if err != nil || !truncated || len(entries) != 2 {
		t.Fatalf("tree: %+v %v %v", entries, truncated, err)
	}
	b, err := c.File(repos[0], "web/bun.lock")
	if err != nil || string(b) != "lock-bytes" {
		t.Fatalf("file: %q %v", b, err)
	}
	total, ranges, err := c.GraphCoverage(repos[0])
	if err != nil || total != 2 || ranges != 1 {
		t.Errorf("graph coverage = %d/%d %v, want 2 packages, 1 range", total, ranges, err)
	}
	if _, err := c.DependabotOpen(repos[0]); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Errorf("dependabot disabled should surface GitHub's message, got %v", err)
	}
	for _, m := range methods {
		if m != http.MethodGet {
			t.Errorf("sent %s; ghread must only GET", m)
		}
	}
}

// Package egress is the only way mamori talks to the network.
//
// Every request goes through Guard. It lets a request out only when its host
// is on the allow list and its method is allowed for that host, and it
// records every host it let through so the report can list them. GitHub is
// GET/HEAD only: mamori cannot write to a repository even if the token could.
package egress

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Errors returned for requests the guard refuses.
var (
	ErrOffline       = errors.New("network is disabled (--offline)")
	ErrHostBlocked   = errors.New("host is not on mamori's allow list")
	ErrMethodBlocked = errors.New("method is not allowed for this host")
)

// Rule says which methods may be sent to a host and why mamori contacts it.
type Rule struct {
	Host    string
	Methods []string
	Purpose string
	// OnlineOnly hosts are allowed only when the user opts into the OSV API.
	OnlineOnly bool
}

// Rules is the complete list of hosts mamori may contact. Nothing else is
// reachable; adding a host means changing this list (and the docs).
var Rules = []Rule{
	{Host: "osv-vulnerabilities.storage.googleapis.com", Methods: []string{"GET", "HEAD"}, Purpose: "public OSV vulnerability database downloads (offline matching)"},
	{Host: "api.github.com", Methods: []string{"GET", "HEAD"}, Purpose: "read repository lists, trees, lockfiles and Dependabot/SBOM status (read-only)"},
	{Host: "raw.githubusercontent.com", Methods: []string{"GET", "HEAD"}, Purpose: "mamori's Patch the Planet data file"},
	{Host: "www.cisa.gov", Methods: []string{"GET", "HEAD"}, Purpose: "CISA Known Exploited Vulnerabilities catalog"},
	{Host: "nodejs.org", Methods: []string{"GET", "HEAD"}, Purpose: "Node.js release list (which releases are security releases)"},
	{Host: "endoflife.date", Methods: []string{"GET", "HEAD"}, Purpose: "end-of-life dates for runtimes"},
	{Host: "api.osv.dev", Methods: []string{"GET", "HEAD", "POST"}, Purpose: "OSV API queries — sends package names and versions; only with --online", OnlineOnly: true},
}

// Policy decides what the guard lets out.
type Policy struct {
	// Offline blocks every request.
	Offline bool
	// Online allows the OnlineOnly rules (the OSV API).
	Online bool
}

// Recorder counts the requests that were let out, per host and method.
type Recorder struct {
	mu   sync.Mutex
	seen map[string]int
}

// NewRecorder returns an empty recorder.
func NewRecorder() *Recorder { return &Recorder{seen: map[string]int{}} }

func (r *Recorder) add(method, host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen[method+" "+host]++
}

// Contacted returns "METHOD host" entries with their counts, sorted.
func (r *Recorder) Contacted() []Contact {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Contact, 0, len(r.seen))
	for k, n := range r.seen {
		method, host, _ := strings.Cut(k, " ")
		out = append(out, Contact{Method: method, Host: host, Requests: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// Contact is one host/method pair the guard let through.
type Contact struct {
	Method   string `json:"method"`
	Host     string `json:"host"`
	Requests int    `json:"requests"`
}

// Guard is an http.RoundTripper that enforces Policy and Rules.
type Guard struct {
	Base     http.RoundTripper
	Policy   Policy
	Recorder *Recorder
}

// RoundTrip implements http.RoundTripper.
func (g *Guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := g.check(req.Method, req.URL.Hostname()); err != nil {
		return nil, fmt.Errorf("mamori egress: %s %s: %w", req.Method, req.URL.Host, err)
	}
	if g.Recorder != nil {
		g.Recorder.add(req.Method, req.URL.Hostname())
	}
	base := g.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func (g *Guard) check(method, host string) error {
	if g.Policy.Offline {
		return ErrOffline
	}
	host = strings.ToLower(host)
	for _, r := range Rules {
		if r.Host != host {
			continue
		}
		if r.OnlineOnly && !g.Policy.Online {
			return ErrHostBlocked
		}
		for _, m := range r.Methods {
			if m == method {
				return nil
			}
		}
		return ErrMethodBlocked
	}
	return ErrHostBlocked
}

// NewClient returns an http.Client whose every request, including redirects,
// passes through a Guard with the given policy.
func NewClient(p Policy, rec *Recorder) *http.Client {
	g := &Guard{Policy: p, Recorder: rec}
	return &http.Client{
		Transport: g,
		Timeout:   10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			// The guard sees the redirected request too, so an allowed host
			// cannot bounce mamori to one that is not on the list.
			return nil
		},
	}
}

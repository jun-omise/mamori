package egress

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// okTransport answers every request with 200 so the tests never touch the network.
type okTransport struct{ calls int }

func (o *okTransport) RoundTrip(*http.Request) (*http.Response, error) {
	o.calls++
	return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}}, nil
}

func do(t *testing.T, g *Guard, method, rawURL string) error {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, rawURL, nil)
	req.URL = u
	req.RequestURI = ""
	_, err = g.RoundTrip(req)
	return err
}

func TestGitHubIsReadOnly(t *testing.T) {
	base := &okTransport{}
	g := &Guard{Base: base, Recorder: NewRecorder()}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if err := do(t, g, m, "https://api.github.com/repos/o/r/issues"); !errors.Is(err, ErrMethodBlocked) {
			t.Errorf("%s to api.github.com: got %v, want ErrMethodBlocked", m, err)
		}
	}
	if err := do(t, g, "GET", "https://api.github.com/user/repos"); err != nil {
		t.Errorf("GET api.github.com: %v", err)
	}
	if base.calls != 1 {
		t.Errorf("only the GET should reach the transport, got %d calls", base.calls)
	}
}

func TestUnknownHostBlocked(t *testing.T) {
	g := &Guard{Base: &okTransport{}}
	for _, u := range []string{"https://example.com/", "https://api.github.com.evil.example/", "https://duckduckgo.com/"} {
		if err := do(t, g, "GET", u); !errors.Is(err, ErrHostBlocked) {
			t.Errorf("GET %s: got %v, want ErrHostBlocked", u, err)
		}
	}
}

func TestOSVAPIOnlyWhenOnline(t *testing.T) {
	g := &Guard{Base: &okTransport{}}
	if err := do(t, g, "POST", "https://api.osv.dev/v1/querybatch"); !errors.Is(err, ErrHostBlocked) {
		t.Errorf("OSV API without --online: got %v, want ErrHostBlocked", err)
	}
	g.Policy.Online = true
	if err := do(t, g, "POST", "https://api.osv.dev/v1/querybatch"); err != nil {
		t.Errorf("OSV API with --online: %v", err)
	}
}

func TestOfflineBlocksEverything(t *testing.T) {
	base := &okTransport{}
	g := &Guard{Base: base, Policy: Policy{Offline: true, Online: true}}
	for _, r := range Rules {
		if err := do(t, g, "GET", "https://"+r.Host+"/"); !errors.Is(err, ErrOffline) {
			t.Errorf("GET %s offline: got %v, want ErrOffline", r.Host, err)
		}
	}
	if base.calls != 0 {
		t.Errorf("offline must not reach the transport, got %d calls", base.calls)
	}
}

func TestRecorderListsWhatWentOut(t *testing.T) {
	rec := NewRecorder()
	g := &Guard{Base: &okTransport{}, Recorder: rec}
	_ = do(t, g, "GET", "https://api.github.com/a")
	_ = do(t, g, "GET", "https://api.github.com/b")
	_ = do(t, g, "POST", "https://api.github.com/c") // blocked, not recorded
	got := rec.Contacted()
	if len(got) != 1 || got[0].Host != "api.github.com" || got[0].Method != "GET" || got[0].Requests != 2 {
		t.Errorf("recorder = %+v", got)
	}
}

func TestOnlyPOSTHostIsOSVAPI(t *testing.T) {
	for _, r := range Rules {
		for _, m := range r.Methods {
			if m != "GET" && m != "HEAD" && r.Host != "api.osv.dev" {
				t.Errorf("%s allows %s; only api.osv.dev may take anything but GET/HEAD", r.Host, m)
			}
		}
	}
}

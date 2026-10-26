package overlay

import (
	"strings"
	"testing"

	"github.com/jun-omise/mamori/internal/version"
)

// The embedded file is what every offline user gets, so it must always be
// well-formed: a CVE per disclosure, a target per product, parseable versions.
func TestEmbeddedIsWellFormed(t *testing.T) {
	d, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Disclosures) == 0 || d.Reviewed == "" {
		t.Fatalf("empty overlay: %+v", d)
	}
	seen := map[string]bool{}
	for _, dis := range d.Disclosures {
		if dis.ID == "" || seen[dis.ID] {
			t.Errorf("missing or duplicate id %q", dis.ID)
		}
		seen[dis.ID] = true
		if len(dis.CVEs) == 0 || !strings.HasPrefix(dis.URL, "https://") {
			t.Errorf("%s: needs CVEs and an https URL", dis.ID)
		}
		for _, p := range dis.Products {
			if (p.Runtime == "") == (p.Package == nil) {
				t.Errorf("%s/%s: exactly one of runtime or package", dis.ID, p.Name)
			}
			switch p.Branch {
			case "major", "minor", "none":
			default:
				t.Errorf("%s/%s: bad branch %q", dis.ID, p.Name, p.Branch)
			}
			for _, f := range p.Fixed {
				if _, ok := version.Parse(f); !ok {
					t.Errorf("%s/%s: unparseable fixed version %q", dis.ID, p.Name, f)
				}
			}
		}
	}
}

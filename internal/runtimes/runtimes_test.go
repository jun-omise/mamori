package runtimes

import (
	"testing"

	"github.com/jun-omise/mamori/overlay"
)

func TestCheckAgainstPatchThePlanet(t *testing.T) {
	data, err := overlay.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	found := []Found{
		{Name: "node", Version: "22.22.2", Path: "/nvm/v22.22.2/bin/node"},
		{Name: "node", Version: "26.12.1", Path: "/opt/homebrew/bin/node"},
		{Name: "node", Version: "20.20.1", Path: "/nvm/v20.20.1/bin/node"},
		{Name: "bun", Version: "1.3.14", Path: "/home/.bun/bin/bun"},
		{Name: "python", Version: "3.11.15", Path: "/venv/bin/python", Packages: map[string]string{"Brotli": "1.2.0"}},
	}
	findings, checked := Check(found, data)
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Package+" "+f.Version] = true
		if f.PatchThePlanet != "brotli" || len(f.IDs) == 0 {
			t.Errorf("finding without its disclosure: %+v", f)
		}
	}
	for _, want := range []string{"Node.js 22.22.2", "Node.js 20.20.1", "Bun 1.3.14", "Brotli 1.2.0"} {
		if !got[want] {
			t.Errorf("missing finding %q; got %v", want, got)
		}
	}
	if got["Node.js 26.12.1"] {
		t.Error("26.12.1 is a fixed release and must not be reported")
	}
	if len(checked["brotli"]) != 3 {
		t.Errorf("checked = %v, want Node.js, Bun and the Python binding", checked["brotli"])
	}
}

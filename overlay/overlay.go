// Package overlay carries the Patch the Planet disclosures that OSV's
// package database does not cover: runtimes such as Node.js, Bun and PHP,
// and upstream libraries bundled inside them.
//
// The data file is reviewed by a person before it lands (see
// .github/workflows/ptp-sync.yml). A copy is compiled into the binary; a
// newer copy is read from the repository when the network is allowed.
package overlay

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

//go:embed patchtheplanet.json
var embedded []byte

// RemoteURL is where newer reviewed data is published.
const RemoteURL = "https://raw.githubusercontent.com/jun-omise/mamori/main/overlay/patchtheplanet.json"

// Data is the whole file.
type Data struct {
	Schema      int          `json:"schema"`
	Source      string       `json:"source"`
	Reviewed    string       `json:"reviewed"`
	Note        string       `json:"note"`
	Disclosures []Disclosure `json:"disclosures"`
}

// Disclosure is one Patch the Planet page.
type Disclosure struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	CVEs       []string  `json:"cves"`
	URL        string    `json:"url"`
	Updated    string    `json:"updated"`
	Summary    string    `json:"summary"`
	Mitigation string    `json:"mitigation"`
	Products   []Product `json:"products"`
}

// Product is something a disclosure names with its fixed releases.
type Product struct {
	Name    string      `json:"name"`
	Runtime string      `json:"runtime,omitempty"`
	Package *PackageRef `json:"package,omitempty"`
	Branch  string      `json:"branch"`
	Fixed   []string    `json:"fixed"`
	Note    string      `json:"note,omitempty"`
}

// PackageRef names a package in an OSV ecosystem.
type PackageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Embedded returns the copy compiled into this binary.
func Embedded() (Data, error) { return parse(embedded) }

func parse(b []byte) (Data, error) {
	var d Data
	if err := json.Unmarshal(b, &d); err != nil {
		return Data{}, fmt.Errorf("overlay: %w", err)
	}
	if d.Schema != 1 {
		return Data{}, fmt.Errorf("overlay: unsupported schema %d", d.Schema)
	}
	return d, nil
}

// Load returns the newest reviewed data: the published copy when client can
// reach it and it parses, otherwise the embedded copy. fromRemote reports
// which one was used.
func Load(client *http.Client) (d Data, fromRemote bool, err error) {
	if client != nil {
		if remote, rerr := fetch(client); rerr == nil && remote.Reviewed >= mustEmbedded().Reviewed {
			return remote, true, nil
		}
	}
	d, err = Embedded()
	return d, false, err
}

func mustEmbedded() Data {
	d, _ := Embedded()
	return d
}

func fetch(client *http.Client) (Data, error) {
	resp, err := client.Get(RemoteURL)
	if err != nil {
		return Data{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Data{}, fmt.Errorf("overlay: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Data{}, err
	}
	return parse(b)
}

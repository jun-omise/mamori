// Package kev reads CISA's Known Exploited Vulnerabilities catalog, so a
// finding that is being exploited in the wild is shown first.
package kev

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// URL is the catalog's public JSON feed.
const URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// MaxAge is how long a cached copy is used before it is downloaded again.
var MaxAge = 24 * time.Hour

// Catalog maps CVE IDs to the date CISA added them.
type Catalog map[string]string

type feed struct {
	Vulnerabilities []struct {
		CVE       string `json:"cveID"`
		DateAdded string `json:"dateAdded"`
	} `json:"vulnerabilities"`
}

// Load returns the catalog from cacheDir, downloading a fresh copy with
// client when the cache is missing or older than MaxAge. With a nil client
// (offline) only the cache is used; stale reports whether it is past MaxAge.
func Load(client *http.Client, cacheDir string) (c Catalog, stale bool, err error) {
	path := filepath.Join(cacheDir, "kev.json")
	info, statErr := os.Stat(path)
	fresh := statErr == nil && time.Since(info.ModTime()) < MaxAge
	if !fresh && client != nil {
		if err := download(client, path); err == nil {
			fresh = true
		} else if statErr != nil {
			return nil, false, err
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("kev: no cached catalog: %w", err)
	}
	var f feed
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, false, fmt.Errorf("kev: %w", err)
	}
	c = Catalog{}
	for _, v := range f.Vulnerabilities {
		c[v.CVE] = v.DateAdded
	}
	return c, !fresh, nil
}

func download(client *http.Client, path string) error {
	resp, err := client.Get(URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kev: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	var f feed
	if err := json.Unmarshal(b, &f); err != nil || len(f.Vulnerabilities) == 0 {
		return fmt.Errorf("kev: unexpected catalog format")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Exploited reports whether any of ids is in the catalog.
func (c Catalog) Exploited(ids []string) bool {
	for _, id := range ids {
		if _, ok := c[id]; ok {
			return true
		}
	}
	return false
}

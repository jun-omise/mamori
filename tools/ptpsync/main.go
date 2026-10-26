// Command ptpsync checks patchtheplanet.org for disclosures that
// overlay/patchtheplanet.json does not cover yet. It runs in CI on a
// schedule, never on users' machines, and only reports: mapping a disclosure
// to products and fixed versions is a reviewed change by a person.
//
// The site has no feed; the disclosure list is read from its current
// JavaScript bundle. Exit 0: nothing new. Exit 10: new disclosures, printed
// as Markdown for an issue. Exit 1: the site could not be read or parsed.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const site = "https://patchtheplanet.org"

var (
	bundleRe = regexp.MustCompile(`src="(/assets/index-[^"]+\.js)"`)
	cveRe    = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	pageRe   = regexp.MustCompile(`"/([a-z0-9][a-z0-9-]{2,40})"`)
)

func get(c *http.Client, url string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return string(b), err
}

func main() {
	overlayPath := "overlay/patchtheplanet.json"
	if len(os.Args) > 1 {
		overlayPath = os.Args[1]
	}
	var known struct {
		Disclosures []struct {
			ID   string   `json:"id"`
			CVEs []string `json:"cves"`
			URL  string   `json:"url"`
		} `json:"disclosures"`
	}
	b, err := os.ReadFile(overlayPath)
	if err == nil {
		err = json.Unmarshal(b, &known)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ptpsync: overlay:", err)
		os.Exit(1)
	}
	have := map[string]bool{}
	pages := map[string]bool{}
	for _, d := range known.Disclosures {
		for _, c := range d.CVEs {
			have[c] = true
		}
		pages[d.ID] = true
	}

	c := &http.Client{Timeout: time.Minute}
	html, err := get(c, site+"/")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ptpsync:", err)
		os.Exit(1)
	}
	m := bundleRe.FindStringSubmatch(html)
	if m == nil {
		fmt.Fprintln(os.Stderr, "ptpsync: bundle not found; the site layout changed")
		os.Exit(1)
	}
	js, err := get(c, site+m[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "ptpsync:", err)
		os.Exit(1)
	}
	cves := uniqSorted(cveRe.FindAllString(js, -1))
	if len(cves) == 0 {
		fmt.Fprintln(os.Stderr, "ptpsync: no CVEs in the bundle; the parser needs attention")
		os.Exit(1)
	}
	var newCVEs, newPages []string
	for _, cve := range cves {
		if !have[cve] {
			newCVEs = append(newCVEs, cve)
		}
	}
	for _, p := range uniqSorted(submatches(pageRe, js)) {
		if !pages[p] && p != "assets" && p != "fonts" && p != "at-a-glance" && p != "xyz" {
			newPages = append(newPages, p)
		}
	}
	if len(newCVEs) == 0 && len(newPages) == 0 {
		fmt.Printf("ptpsync: up to date (%d CVEs on the site, all covered)\n", len(cves))
		return
	}
	fmt.Println("Patch the Planet lists disclosures that `overlay/patchtheplanet.json` does not cover yet.")
	fmt.Println()
	fmt.Println("A person needs to read each one, map it to the affected products and their fixed versions, and update the overlay in a pull request.")
	fmt.Println()
	for _, cve := range newCVEs {
		fmt.Printf("- [ ] %s — https://www.cve.org/CVERecord?id=%s\n", cve, cve)
	}
	for _, p := range newPages {
		fmt.Printf("- [ ] new page: %s/%s\n", site, p)
	}
	os.Exit(10)
}

func submatches(re *regexp.Regexp, s string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

func uniqSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

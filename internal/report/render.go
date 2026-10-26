package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Lang is "ja" or "en".
type Lang string

var msg = map[string][2]string{ // [ja, en]
	"title": {"mamori スキャン結果", "mamori scan report"},
	"mode":  {"照合の方法", "Matching"},
	"mode.offline": {"手元で照合(公開データベースを落として照らし、パッケージの一覧は外に送っていません)",
		"local matching (public databases downloaded; your package list was not sent anywhere)"},
	"mode.strict": {"完全オフライン(通信なし・手元のキャッシュだけで照合)", "strict offline (no network; cached databases only)"},
	"mode.online": {"OSV の API で照合(パッケージ名と版を api.osv.dev に送りました)",
		"OSV API (package names and versions were sent to api.osv.dev)"},
	"summary":                  {"まとめ", "Summary"},
	"scanned":                  {"調べたもの", "What was scanned"},
	"findings":                 {"問題", "Findings"},
	"none":                     {"見つかった問題はありません。", "No problems found."},
	"none.blind":               {"見つかった問題はありませんが、読めなかったものがあります。下の一覧を見てください。「問題なし」とは言えません。", "No problems found, but some things could not be read (see below). This is not a clean result."},
	"blind":                    {"読めなかったもの・判断できなかったもの", "Blind spots (could not read or judge)"},
	"ptp":                      {"Patch the Planet の公開", "Patch the Planet disclosures"},
	"egress":                   {"通信した宛先", "Network contacts"},
	"egress.none":              {"通信はしていません。", "No network requests were made."},
	"notes":                    {"注意", "Notes"},
	"files":                    {"ファイル", "files"},
	"packages":                 {"パッケージ", "packages"},
	"fixed":                    {"直った版", "fixed in"},
	"nofix":                    {"直った版なし", "no fixed version"},
	"kev":                      {"悪用が確認済み(CISA KEV)", "known exploited (CISA KEV)"},
	"malicious":                {"悪意のあるパッケージ", "malicious package"},
	"checked":                  {"確かめたもの", "checked"},
	"manual":                   {"手で確かめてください", "check by hand"},
	"affected":                 {"当たった数", "findings"},
	"runtimes":                 {"実行環境", "runtimes"},
	"requests":                 {"回", "requests"},
	"reason.unreadable-format": {"この形式は読めません(bun.lockb は `bun install --save-text-lockfile` で bun.lock に)", "this lockfile format cannot be read (turn bun.lockb into bun.lock with `bun install --save-text-lockfile`)"},
	"reason.not-parsed":        {"このファイルから何も読み取れませんでした(空・未対応の書き方・パッケージなし)", "nothing could be read from this file (empty, unsupported variant, or no packages)"},
	"reason.no-lockfile":       {"依存は書かれていますが、隣にロックファイルが無いので、実際に入る版が分かりません", "dependencies are declared but there is no lockfile next to them, so the installed versions are unknown"},
	"reason.tree-truncated":    {"リポジトリが大きく、GitHub がファイルの一覧を途中で切りました。一部のロックファイルを見ていない可能性があります", "GitHub truncated the file list of this large repository; some lockfiles may not have been seen"},
	"reason.submodule":         {"git のサブモジュールです。そのリポジトリを別に調べてください", "git submodule; scan its repository separately"},
	"reason.fetch-failed":      {"ファイルを読めませんでした", "the file could not be downloaded"},
	"reason.repo-failed":       {"リポジトリを読めませんでした", "the repository could not be read"},
	"reason.graph-blind":       {"GitHub の依存グラフはこのリポジトリのロックファイルを読めていません(版が範囲のまま)。Dependabot の警告が少なくても安全とは言えません", "GitHub's dependency graph is not reading this repository's lockfile (versions are still ranges), so a quiet Dependabot does not mean safe"},
	"reason.no-db":             {"脆弱性データベースが手元にありません。一度ネットにつないで実行してください", "no local vulnerability database yet; run once with the network allowed"},
	"reason.scan-failed":       {"照合に失敗しました", "matching failed"},
	"reason.kev-missing":       {"CISA の悪用確認済みの一覧を読めませんでした。悪用中かどうかの印は付いていません", "the CISA KEV catalog could not be read; findings are not marked as exploited"},
}

func t(l Lang, k string) string {
	m, ok := msg[k]
	if !ok {
		return k
	}
	if l == "en" {
		return m[1]
	}
	return m[0]
}

var sevJA = map[string]string{"critical": "重大", "high": "高", "medium": "中", "low": "低", "unknown": "不明"}

func sev(l Lang, s string) string {
	if l == "en" {
		return s
	}
	return sevJA[s]
}

func modeText(l Lang, mode string) string {
	switch mode {
	case "strict-offline":
		return t(l, "mode.strict")
	case "online":
		return t(l, "mode.online")
	default:
		return t(l, "mode.offline")
	}
}

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Text writes a plain-text report for a terminal.
func Text(w io.Writer, r *Report, l Lang) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p("%s — %s %s\n", t(l, "title"), r.Tool, r.Version)
	p("%s: %s\n\n", t(l, "mode"), modeText(l, r.Mode))

	c := r.Counts()
	p("== %s\n", t(l, "summary"))
	p("  %s: critical %d / high %d / medium %d / low %d / unknown %d\n", t(l, "findings"),
		c["critical"], c["high"], c["medium"], c["low"], c["unknown"])
	p("  %s: %d\n\n", t(l, "blind"), len(r.BlindSpots))

	p("== %s\n", t(l, "scanned"))
	for _, tg := range r.Targets {
		pk := 0
		for _, f := range tg.Files {
			pk += f.Packages
		}
		switch tg.Kind {
		case "runtimes":
			p("  [%s] %s\n", tg.Kind, t(l, "runtimes"))
			for _, rt := range tg.Runtimes {
				p("      %s %s  (%s)\n", rt.Name, rt.Version, rt.Path)
			}
		default:
			p("  [%s] %s — %d %s, %d %s\n", tg.Kind, tg.Name, len(tg.Files), t(l, "files"), pk, t(l, "packages"))
			for _, f := range tg.Files {
				p("      %s  (%s, %d)\n", f.Path, f.Ecosystem, f.Packages)
			}
		}
		for _, k := range sortedKeys(tg.Facts) {
			p("      - %s: %s\n", k, tg.Facts[k])
		}
	}
	p("\n== %s\n", t(l, "findings"))
	if len(r.Findings) == 0 {
		if len(r.BlindSpots) > 0 {
			p("  %s\n", t(l, "none.blind"))
		} else {
			p("  %s\n", t(l, "none"))
		}
	}
	for i, f := range r.Findings {
		flags := []string{sev(l, f.Severity)}
		if f.KEV {
			flags = append(flags, t(l, "kev"))
		}
		if f.Kind == "malicious" {
			flags = append(flags, t(l, "malicious"))
		}
		p("  %d. [%s] %s %s  — %s\n", i+1, strings.Join(flags, " · "), f.Package, f.Version, f.Target)
		p("     %s\n", f.Location)
		p("     %s  %s\n", strings.Join(f.IDs, ", "), f.Summary)
		if len(f.Fixed) > 0 {
			p("     %s: %s\n", t(l, "fixed"), strings.Join(f.Fixed, ", "))
		} else {
			p("     %s\n", t(l, "nofix"))
		}
		if f.Advice != "" {
			p("     → %s\n", f.Advice)
		}
	}
	p("\n== %s\n", t(l, "blind"))
	if len(r.BlindSpots) == 0 {
		p("  -\n")
	}
	for _, b := range r.BlindSpots {
		loc := b.Target
		if b.Path != "" {
			loc += ":" + b.Path
		}
		p("  - %s — %s\n", loc, reason(l, b))
	}
	if len(r.Disclosure) > 0 {
		p("\n== %s\n", t(l, "ptp"))
		for _, d := range r.Disclosure {
			p("  %s (%s) %s\n", d.Title, strings.Join(d.CVEs, ", "), d.URL)
			p("     %s: %s / %s: %d\n", t(l, "checked"), joinOrDash(d.Checked), t(l, "affected"), d.Affected)
			if len(d.Manual) > 0 {
				p("     %s: %s\n", t(l, "manual"), strings.Join(d.Manual, ", "))
			}
		}
	}
	if len(r.Notes) > 0 {
		p("\n== %s\n", t(l, "notes"))
		for _, n := range r.Notes {
			p("  - %s\n", n)
		}
	}
	p("\n== %s\n", t(l, "egress"))
	if len(r.Egress) == 0 {
		p("  %s\n", t(l, "egress.none"))
	}
	for _, e := range r.Egress {
		p("  %s %s  (%d %s)\n", e.Method, e.Host, e.Requests, t(l, "requests"))
	}
}

// Markdown writes the report as Markdown, for issues and pull requests.
func Markdown(w io.Writer, r *Report, l Lang) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p("# %s\n\n", t(l, "title"))
	p("%s %s · %s: %s\n\n", r.Tool, r.Version, t(l, "mode"), modeText(l, r.Mode))
	c := r.Counts()
	p("**%s**: critical %d · high %d · medium %d · low %d · unknown %d — **%s**: %d\n\n",
		t(l, "findings"), c["critical"], c["high"], c["medium"], c["low"], c["unknown"], t(l, "blind"), len(r.BlindSpots))

	p("## %s\n\n", t(l, "findings"))
	if len(r.Findings) == 0 {
		if len(r.BlindSpots) > 0 {
			p("%s\n\n", t(l, "none.blind"))
		} else {
			p("%s\n\n", t(l, "none"))
		}
	} else {
		p("| # | | Package | Version | %s | IDs | Where |\n|---|---|---|---|---|---|---|\n", t(l, "fixed"))
		for i, f := range r.Findings {
			flag := sev(l, f.Severity)
			if f.KEV {
				flag += " · KEV"
			}
			if f.Kind == "malicious" {
				flag += " · " + t(l, "malicious")
			}
			fixed := strings.Join(f.Fixed, ", ")
			if fixed == "" {
				fixed = "—"
			}
			p("| %d | %s | `%s` | %s | %s | %s | %s `%s` |\n", i+1, flag, f.Package, f.Version, fixed,
				strings.Join(f.IDs, " "), mdEscape(f.Target), mdEscape(f.Location))
		}
		p("\n")
	}
	p("## %s\n\n", t(l, "blind"))
	if len(r.BlindSpots) == 0 {
		p("—\n\n")
	}
	for _, b := range r.BlindSpots {
		loc := b.Target
		if b.Path != "" {
			loc += ":" + b.Path
		}
		p("- `%s` — %s\n", loc, reason(l, b))
	}
	p("\n## %s\n\n", t(l, "scanned"))
	for _, tg := range r.Targets {
		if tg.Kind == "runtimes" {
			for _, rt := range tg.Runtimes {
				p("- runtime: %s %s (`%s`)\n", rt.Name, rt.Version, rt.Path)
			}
			continue
		}
		pk := 0
		for _, f := range tg.Files {
			pk += f.Packages
		}
		p("- %s `%s`: %d %s, %d %s\n", tg.Kind, tg.Name, len(tg.Files), t(l, "files"), pk, t(l, "packages"))
		for _, f := range tg.Files {
			p("  - `%s` (%s, %d)\n", f.Path, f.Ecosystem, f.Packages)
		}
		for _, k := range sortedKeys(tg.Facts) {
			p("  - %s: %s\n", k, tg.Facts[k])
		}
	}
	if len(r.Disclosure) > 0 {
		p("\n## %s\n\n", t(l, "ptp"))
		for _, d := range r.Disclosure {
			p("- [%s](%s) (%s): %s %s; %s %d", d.Title, d.URL, strings.Join(d.CVEs, ", "),
				t(l, "checked"), joinOrDash(d.Checked), t(l, "affected"), d.Affected)
			if len(d.Manual) > 0 {
				p("; %s: %s", t(l, "manual"), strings.Join(d.Manual, ", "))
			}
			p("\n")
		}
	}
	p("\n## %s\n\n", t(l, "egress"))
	if len(r.Egress) == 0 {
		p("%s\n", t(l, "egress.none"))
	}
	for _, e := range r.Egress {
		p("- `%s %s` (%d)\n", e.Method, e.Host, e.Requests)
	}
}

func reason(l Lang, b BlindSpot) string {
	if _, ok := msg["reason."+b.Code]; ok {
		text := t(l, "reason."+b.Code)
		switch b.Code {
		case "fetch-failed", "repo-failed", "scan-failed":
			if b.Reason != "" {
				text += ": " + b.Reason
			}
		}
		return text
	}
	return b.Reason
}

func joinOrDash(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, ", ")
}

func mdEscape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

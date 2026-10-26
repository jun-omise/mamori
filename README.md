<div align="center">

# mamori

**A read-only vulnerability scanner for your dependencies, your GitHub repositories,
and the machine you run it on.**

**English** · [日本語](README.ja.md)

[![ci](https://github.com/jun-omise/mamori/actions/workflows/ci.yml/badge.svg)](https://github.com/jun-omise/mamori/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

</div>

<p align="center">
  <a href="https://jun-omise.github.io/mamori/?lang=en">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://jun-omise.github.io/mamori/media/mamori-demo-en-dark.gif">
      <img src="https://jun-omise.github.io/mamori/media/mamori-demo-en-light.gif" width="800" alt="30-second animation of how mamori works: what it reads, the gate every request passes, local matching, the three-part report, and exit codes">
    </picture>
  </a>
  <br>
  <sub>How mamori works, in 30 seconds · <a href="https://jun-omise.github.io/mamori/?lang=en">open the interactive version</a> (pause, chapters, try the gate)</sub>
</p>

**mamori** (守り, "protection") runs on macOS, Windows and Linux as a single file. It reads your
lockfiles locally or straight from GitHub — without cloning and without write access — matches them
against public vulnerability data **on your machine**, and always answers three questions:

1. **What was scanned?** Every file, package count and runtime, so you know what "no findings" covers.
2. **What is wrong?** Each finding with its advisory IDs, the version that fixes it, and whether it is
   being exploited in the wild.
3. **What could not be read?** Files, folders and repositories mamori could not judge. A scan with
   blind spots is never reported as clean.

## Contents

- [Quick start](#quick-start) · [Sample output](#sample-output) · [Why you can trust it](#why-you-can-trust-it)
- [What it checks](#what-it-checks) · [Install](#install) · [Usage](#usage) · [Use in CI](#use-in-ci)
- [GitHub token](#github-token) · [Exit codes](#exit-codes) · [Network contacts](#network-contacts)
- [FAQ](#faq) · [Roadmap](#roadmap) · [Contributing](#contributing) · [License](#license)

## Quick start

```bash
mamori scan                                   # this folder + the runtimes installed on this machine
mamori scan --github your-org                 # every repository of a user or organization, read-only
mamori scan --github owner/repo --format markdown --out report.md
mamori egress                                 # every host mamori may contact, and why
```

## Sample output

A demo folder with deliberately old versions (trimmed; the full report lists all nine findings):

```text
mamori scan report — mamori v0.1.0
Matching: local matching (public databases downloaded; your package list was not sent anywhere)

== Summary
  Findings: critical 5 / high 1 / medium 3 / low 0 / unknown 0
  Blind spots (could not read or judge): 1

== What was scanned
  [local] ~/my-app — 2 files, 5 packages
      api/requirements.txt  (PyPI, 2)
      web/package-lock.json  (npm, 3)

== Findings
  1. [critical] @tanstack/react-start 1.167.50  — local:~/my-app
     web/package-lock.json
     GHSA-qx66-fv34-fjm8, CVE-2026-102989  TanStack Router: Unauthenticated reflected XSS in TanStack Start server-function responses
     fixed in: 1.168.60
  3. [critical] brotli 1.2.0  — local:~/my-app
     api/requirements.txt
     GHSA-9v8h-qqgm-4m35, CVE-2026-111497, …  Out-of-bounds write in the Brotli decoder ("Node2Shell") also affects the PyPI Brotli package
     fixed in: 1.2.1
  4. [critical] seroval 1.5.2  — local:~/my-app
     web/package-lock.json
     GHSA-mv8w-475r-vwqw, CVE-2026-59940  seroval: `seroval.fromJSON()` Promise resolver type confusion invokes attacker-controlled methods during deserialization
     fixed in: 1.5.3
  …

== Blind spots (could not read or judge)
  - local:~/my-app:worker/package.json — dependencies are declared but there is no lockfile next to them, so the installed versions are unknown

== Patch the Planet disclosures
  Brotli decoder vulnerability (CVE-2026-111497) https://patchtheplanet.org/brotli
     checked: Google Brotli (Python binding) / findings: 1
     check by hand: Node.js, Bun, Envoy Proxy, Istio

== Network contacts
  HEAD osv-vulnerabilities.storage.googleapis.com  (2 req.)
  GET raw.githubusercontent.com  (1 req.)
```

The same report is available as Markdown (for issues and pull requests) and JSON (for other tools).

## Why you can trust it

| Promise | How it is kept |
|---|---|
| **It cannot change anything on GitHub.** | Every request goes through one guard ([`internal/egress`](internal/egress/egress.go)) that refuses any method but `GET`/`HEAD` for `api.github.com`. [Tests](internal/egress/egress_test.go) prove it. A token that could write is still only used to read, and mamori warns you about it. |
| **Your code and package list stay on your machine.** | By default mamori downloads the public [OSV](https://osv.dev) database (only when it changed) and matches **locally**. Nothing about your dependencies is sent anywhere. Sending package names to the OSV API is an explicit opt-in (`--online`). |
| **You can see every host it talks to.** | `mamori egress` prints the complete allow list with the reason for each host. Every report ends with the hosts actually contacted. `--offline` makes no network requests at all. |
| **No telemetry, no self-update.** | mamori never phones home and never replaces its own binary. Data (vulnerability databases, the Patch the Planet file) is refreshed; code is not. |
| **"No findings" is never silent.** | Unparseable files, manifests without a lockfile, missing databases, npm packages without a registry source, truncated repository listings, submodules, and repositories whose GitHub dependency graph is not reading the lockfile are all listed as **blind spots**, and the exit code is `3`, not `0`. Ignore rules in `osv-scanner.toml` are always named in the report. |
| **The matching is not ours.** | Version matching is done by Google's [OSV-Scanner](https://github.com/google/osv-scanner) library (Apache-2.0), used as-is. mamori decides what to read and how to report it. |
| **You can verify what you run.** | Releases are built by GitHub Actions from a tagged commit, reproducibly (`CGO_ENABLED=0 -trimpath -buildid=`: two builds are byte-identical), with `SHA256SUMS` and signed build provenance. |

## What it checks

**Lockfiles** — whatever OSV-Scanner reads, including `bun.lock`, `package-lock.json`, `pnpm-lock.yaml`,
`yarn.lock`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements*.txt`, `Cargo.lock`, `go.mod`,
`Gemfile.lock`, `composer.lock`, NuGet and Maven/Gradle lockfiles.

**GitHub repositories, read-only** — lists an owner's repositories, reads each file tree, downloads only
the lockfiles (no clone), and shows Dependabot's own alert count next to mamori's findings. It also reads
GitHub's dependency graph: when most versions there are still ranges, GitHub is not reading your
lockfile, and a quiet Dependabot means little. mamori says so.

**Runtimes on this machine** — every Node.js it can find (PATH, nvm, nvm-windows, volta, fnm), Bun, PHP,
Envoy, Istio, and Python with the Brotli packages installed in it. Node.js is also checked against
nodejs.org for missed security releases and end-of-life release lines.

**[Patch the Planet](https://patchtheplanet.org/) disclosures** — a reviewed data file
([`overlay/patchtheplanet.json`](overlay/patchtheplanet.json)) maps each disclosure to the affected
products and their fixed versions. A daily job opens an issue when the site lists something new, and a
person updates the file in a pull request. Your copy of mamori never scrapes the site.

**Exploited in the wild** — findings in CISA's
[Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog
are marked and listed first.

**Folders it does not walk** — `node_modules`, `.venv`, `venv`, `__pycache__` and `.git` hold installed
copies; the lockfile next to them is scanned instead, and the report counts what was skipped.

Not in this version: container images, operating-system packages, secrets, source-code analysis, and
hosts other than GitHub. See the [roadmap](#roadmap).

## Install

Pre-built files for macOS, Windows and Linux (Intel and Arm) are published on
[Releases](https://github.com/jun-omise/mamori/releases) starting with v0.1.0.
**Verify a file before you run it.**

### macOS and Linux

```bash
gh attestation verify mamori-v0.1.0-darwin-arm64 --repo jun-omise/mamori
shasum -a 256 -c SHA256SUMS --ignore-missing
chmod +x mamori-v0.1.0-darwin-arm64 && mv mamori-v0.1.0-darwin-arm64 /usr/local/bin/mamori
```

### Windows (PowerShell)

```powershell
gh attestation verify .\mamori-v0.1.0-windows-amd64.exe --repo jun-omise/mamori
(Get-FileHash .\mamori-v0.1.0-windows-amd64.exe -Algorithm SHA256).Hash   # compare with SHA256SUMS
Rename-Item .\mamori-v0.1.0-windows-amd64.exe mamori.exe
```

### From source (Go 1.27 or later)

```bash
go install github.com/jun-omise/mamori/cmd/mamori@latest
```

The release files are not yet signed with Apple or Microsoft code-signing certificates, so macOS
Gatekeeper and Windows SmartScreen may warn on first run. The provenance check above
(`gh attestation verify`, GitHub CLI 2.49 or later) is the verification that matters.

## Usage

```text
mamori scan [targets] [flags]
mamori egress
mamori version
```

| Flag | Meaning |
|---|---|
| `--local PATH` | scan a folder (repeatable). With no targets, mamori scans `.` and `--runtimes` |
| `--github OWNER` / `--github OWNER/REPO` | scan every repository of an owner, or one repository (repeatable) |
| `--runtimes` | check Node.js, Bun, PHP, Envoy, Istio and Python installed on this machine |
| `--include-forks`, `--include-archived` | also scan forks and archived repositories |
| `--online` | match with the OSV API instead of locally (sends package names and versions to api.osv.dev) |
| `--offline` | no network at all; use the cached databases |
| `--format text\|markdown\|json` | output format (default `text`) |
| `--out FILE` | write the report to a file |
| `--lang ja\|en` | report language (default: the system language; on Windows `LANG` is usually unset, so pass `--lang ja` for Japanese) |
| `--cache-dir DIR` | where databases are kept (default: your user cache folder) |
| `--verbose` | show OSV-Scanner's own log |

## Use in CI

```yaml
- uses: actions/setup-go@v7
  with:
    go-version: "1.27"
- name: mamori
  run: |
    go install github.com/jun-omise/mamori/cmd/mamori@v0.1.0
    set +e
    mamori scan --local . --format markdown --out mamori.md
    code=$?
    cat mamori.md >> "$GITHUB_STEP_SUMMARY"
    exit $code   # 1 = findings, 3 = blind spots
```

Pin both the action and the mamori version you have reviewed.

## GitHub token

mamori only needs to **read**. Create a
[fine-grained personal access token](https://github.com/settings/personal-access-tokens/new) with:

- **Repository access**: the repositories you want to scan
- **Permissions**: Contents: Read-only, Metadata: Read-only, and optionally Dependabot alerts: Read-only

Set it as `MAMORI_GITHUB_TOKEN`. mamori also picks up `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token`
(set `MAMORI_NO_GH_CLI=1` to stop it from running `gh`), and tells you when the token could write.
Without a token, public repositories can be read at 60 requests per hour.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | scanned; nothing found and nothing left unread |
| `1` | findings |
| `2` | mamori could not run |
| `3` | nothing found, but something could not be read — **not** a clean result |

## Network contacts

| Host | Methods | Why |
|---|---|---|
| `osv-vulnerabilities.storage.googleapis.com` | GET, HEAD | public OSV database downloads |
| `api.github.com` | GET, HEAD | repository lists, file trees, lockfiles, Dependabot and dependency-graph status |
| `raw.githubusercontent.com` | GET, HEAD | newer reviewed Patch the Planet data |
| `www.cisa.gov` | GET, HEAD | Known Exploited Vulnerabilities catalog (cached for a day) |
| `nodejs.org`, `endoflife.date` | GET, HEAD | Node.js security releases and end-of-life dates |
| `api.osv.dev` | GET, HEAD, POST | **only with `--online`**; sends package names and versions |

Nothing else is reachable. Adding a host means changing [`internal/egress`](internal/egress/egress.go)
and this table in the same pull request.

## FAQ

### Does mamori send my code or dependency list anywhere?

No, not by default. It downloads public data and matches on your machine. Only `--online` sends package
names and versions, to api.osv.dev. Check any run's "Network contacts" section.

### How is this different from Dependabot?

Use both. Dependabot watches a repository from GitHub's side; mamori shows what it scanned and what it
could not. One example: when GitHub's dependency graph does not read a lockfile (it lists ranges such
as `^1.167.50` instead of the installed versions), Dependabot cannot see the real versions and can stay
quiet. mamori reads the lockfile itself and reports that gap as a blind spot.

### How is this different from OSV-Scanner?

mamori uses OSV-Scanner for matching. It adds read-only scanning of GitHub without cloning, runtime
checks, Patch the Planet data, the CISA KEV mark, blind-spot reporting, and an egress guard.

### Why do I see blind spots?

Because mamori could not judge something: a manifest with no lockfile, a file it could not parse, a
missing database, or a repository GitHub could not list in full. Each line says what to do.

### Why is the file about 40 MB?

It contains OSV-Scanner's readers for many ecosystems and needs no other runtime.

## Roadmap

- Package managers: Homebrew, winget, Scoop
- Apple and Microsoft code signing
- SARIF output for GitHub code scanning
- GitLab and other hosts
- Container images

## Contributing

Issues and pull requests are welcome. Run `go vet ./...` and `go test ./...` before sending a change.
Updates to [`overlay/patchtheplanet.json`](overlay/patchtheplanet.json) need a link to the disclosure page
for every fixed version. Please report vulnerabilities in mamori privately; see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE). Built on [OSV-Scanner](https://github.com/google/osv-scanner) (Apache-2.0), with
vulnerability data from [OSV](https://osv.dev), the [GitHub Advisory Database](https://github.com/advisories),
the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and
[Patch the Planet](https://patchtheplanet.org/).

# mamori

**mamori** (守り, "protection") is a read-only vulnerability scanner for the code you
depend on and the machine you run it on. It runs on macOS, Windows and Linux as a
single file, reads your lockfiles locally or straight from GitHub, and tells you
three things: **what it scanned, what is wrong, and what it could not read.**

[日本語の説明はこちら](README.ja.md)

```
mamori scan                                  # this folder + this machine's runtimes
mamori scan --github my-org                  # every repository of an org, read-only
mamori scan --github owner/repo --format markdown --out report.md
```

## Why you can trust it

| Promise | How it is kept |
|---|---|
| **It cannot change anything on GitHub.** | Every request goes through one guard ([`internal/egress`](internal/egress/egress.go)) that refuses any method but `GET`/`HEAD` for `api.github.com`. Tests prove it. A token that could write is still only used to read, and mamori warns you about it. |
| **Your code and package list stay on your machine.** | By default mamori downloads the public [OSV](https://osv.dev) vulnerability database (only when it changed) and matches **locally**. Nothing about your dependencies is sent anywhere. Sending package names to the OSV API is an explicit opt-in (`--online`). |
| **You can see every host it talks to.** | `mamori egress` prints the complete allow list with the reason for each host. Every report ends with the hosts actually contacted and how many requests. `--offline` makes no network requests at all. |
| **No telemetry, no self-update.** | mamori never phones home and never replaces its own binary. You update it through your package manager or a release you verified. Data (vulnerability databases, the Patch the Planet file) is refreshed; code is not. |
| **"No findings" is never silent.** | Files it could not parse, manifests without a lockfile, missing databases, truncated repository listings, and repositories where GitHub's own dependency graph is not reading the lockfile are listed as **blind spots**, and the exit code is `3`, not `0`. |
| **The matching is not ours.** | Version matching is done by Google's [OSV-Scanner](https://github.com/google/osv-scanner) library (Apache-2.0), used as-is. mamori decides what to read and how to report it. |
| **You can verify what you run.** | Releases are built by GitHub Actions from a tagged commit, reproducibly (`CGO_ENABLED=0 -trimpath -buildid=`), with `SHA256SUMS` and signed build provenance. |

## What it checks

- **Lockfiles**: `bun.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `uv.lock`,
  `poetry.lock`, `Pipfile.lock`, `requirements*.txt`, `Cargo.lock`, `go.mod`, `Gemfile.lock`,
  `composer.lock`, NuGet, Maven/Gradle lockfiles and more — whatever OSV-Scanner reads.
- **GitHub repositories, read-only**: lists an owner's repositories, reads each tree, downloads only
  the lockfiles (no clone), and reports Dependabot's own alert count next to mamori's findings. It also
  reads GitHub's dependency graph: when most versions there are ranges, GitHub is not reading your
  lockfile, so a quiet Dependabot means little — mamori says so.
- **Runtimes on this machine**: every Node.js it can find (PATH, nvm, nvm-windows, volta, fnm), Bun,
  PHP, Envoy, Istio, Python and the Brotli packages installed in it. Node.js is also checked against
  nodejs.org for missed security releases and end-of-life lines.
- **[Patch the Planet](https://patchtheplanet.org/) disclosures**: a reviewed data file
  ([`overlay/patchtheplanet.json`](overlay/patchtheplanet.json)) maps each disclosure to products and
  fixed versions. A daily job opens an issue when the site lists something new; a person updates the
  file. Your copy of mamori never scrapes the site.
- **Known exploited**: findings listed in CISA's
  [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  catalog are marked and shown first.

Not in this version: container images, OS packages, secrets, and source-code analysis. GitLab and
other hosts are planned.

## Install

Download the file for your platform from [Releases](https://github.com/jun-omise/mamori/releases),
then verify it before running:

```bash
gh attestation verify mamori-v0.1.0-darwin-arm64 --repo jun-omise/mamori
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Or build from source (Go 1.27+):

```bash
go install github.com/jun-omise/mamori/cmd/mamori@latest
```

The release binaries are not yet signed with Apple or Microsoft code-signing certificates, so macOS
Gatekeeper and Windows SmartScreen may warn on first run. The provenance check above is the
verification that matters.

## GitHub token

mamori only needs to **read**. Create a
[fine-grained personal access token](https://github.com/settings/personal-access-tokens/new) with:

- Repository access: the repositories you want to scan
- Permissions: **Contents: Read-only**, **Metadata: Read-only**, and optionally
  **Dependabot alerts: Read-only**

and set it as `MAMORI_GITHUB_TOKEN`. mamori also picks up `GITHUB_TOKEN`, `GH_TOKEN`, or
`gh auth token`, and tells you when that token could write. Without a token, public repositories
can be read at 60 requests per hour.

## Output and exit codes

`--format text` (default), `markdown` (for issues and pull requests) or `json`. `--lang ja|en`.

| Exit | Meaning |
|---|---|
| 0 | scanned, nothing found, nothing unread |
| 1 | findings |
| 2 | mamori could not run |
| 3 | nothing found, but some things could not be read — not a clean result |

## Network contacts

| Host | Methods | Why |
|---|---|---|
| osv-vulnerabilities.storage.googleapis.com | GET, HEAD | public OSV database downloads |
| api.github.com | GET, HEAD | repository lists, trees, lockfiles, Dependabot/SBOM status |
| raw.githubusercontent.com | GET, HEAD | newer reviewed Patch the Planet data |
| www.cisa.gov | GET, HEAD | Known Exploited Vulnerabilities catalog |
| nodejs.org, endoflife.date | GET, HEAD | Node.js security releases and end-of-life dates |
| api.osv.dev | GET, HEAD, POST | **only with `--online`**; sends package names and versions |

## Reporting a vulnerability in mamori

See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. Built on [OSV-Scanner](https://github.com/google/osv-scanner) (Apache-2.0) and
vulnerability data from [OSV](https://osv.dev), [GitHub Advisory Database](https://github.com/advisories),
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and
[Patch the Planet](https://patchtheplanet.org/).

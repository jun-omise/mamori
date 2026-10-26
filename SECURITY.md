# Security policy

mamori is a security tool, so a flaw in it matters twice. Please report
vulnerabilities **privately**, not in a public issue.

## How to report

Use GitHub's private vulnerability reporting: open the **Security** tab of
this repository and choose **Report a vulnerability**. Include what you ran,
what happened, and what you expected.

We aim to acknowledge a report within 3 working days and to publish a fixed
release and a GitHub Security Advisory once a fix is ready.

## What is in scope

- mamori sending any request other than GET/HEAD to GitHub, or contacting a
  host that is not listed by `mamori egress`
- mamori sending package names, versions or file contents anywhere in the
  default or `--offline` modes
- a report that says "no findings" (exit code 0) when something could not be
  read
- tampered or unverifiable release files

## Supported versions

Only the latest release receives fixes.

#!/usr/bin/env bash
# Builds every release file the same way on a laptop and in CI, so anyone can
# rebuild a release and compare it byte for byte with SHA256SUMS.
#
#   scripts/build-release.sh v0.1.0 dist
#
# Reproducible: no cgo, trimmed paths, no build id, no VCS stamp. The same Go
# version and the same commit give the same bytes.
set -euo pipefail

version="${1:?usage: build-release.sh VERSION [OUTDIR]}"
out="${2:-dist}"
mkdir -p "$out"

for target in darwin/arm64 darwin/amd64 windows/amd64 windows/arm64 linux/amd64 linux/arm64; do
  os=${target%/*}
  arch=${target#*/}
  ext=""
  if [ "$os" = windows ]; then ext=.exe; fi
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid= -X main.Version=${version}" \
    -o "$out/mamori-${version}-${os}-${arch}${ext}" ./cmd/mamori
done

cd "$out"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum mamori-* > SHA256SUMS
else
  shasum -a 256 mamori-* > SHA256SUMS
fi
cat SHA256SUMS

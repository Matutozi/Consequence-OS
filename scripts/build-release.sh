#!/usr/bin/env bash
# Builds release archives into dist/: one .tar.gz per platform holding
# consequenced, mockmcp, the licence, the README and an example config,
# plus SHA256SUMS. The release workflow runs this; so does `make dist`.
#
#   scripts/build-release.sh v0.1.0
set -euo pipefail

VERSION="${1:?usage: $0 <version, e.g. v0.1.0>}"
PLATFORMS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64)

rm -rf dist
mkdir -p dist

for platform in "${PLATFORMS[@]}"; do
  os="${platform%/*}" arch="${platform#*/}"
  name="consequenceos_${VERSION}_${os}_${arch}"
  stage="dist/$name"
  mkdir -p "$stage"
  for cmd in consequenced mockmcp; do
    # CGO off gives static binaries; -trimpath drops local paths from them.
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
      -ldflags "-s -w -X main.version=$VERSION" -o "$stage/$cmd" "./cmd/$cmd"
  done
  cp LICENSE README.md "$stage/"
  cp consequence.yaml "$stage/consequence.example.yaml"
  tar -C dist -czf "dist/$name.tar.gz" "$name"
  rm -rf "$stage"
  echo "built dist/$name.tar.gz"
done

(cd dist && sha256sum -- *.tar.gz > SHA256SUMS)
echo "wrote dist/SHA256SUMS"

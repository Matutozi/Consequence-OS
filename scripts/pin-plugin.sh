#!/usr/bin/env bash
# Points the Claude Code plugin at a published release: the version its
# launcher installs, the plugin's own version, and that release's
# SHA256SUMS, copied into the plugin. The launcher runs only an archive
# that matches those checksums. Run it after the release is published,
# then commit the plugin folder.
#
#   scripts/pin-plugin.sh v0.6.0
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:?usage: $0 <a published version, e.g. v0.6.0>}"
plugin=plugins/consequenceos
sums="$(curl -fsSL --proto '=https' --tlsv1.2 \
  "https://github.com/Matutozi/Consequence-OS/releases/download/$VERSION/SHA256SUMS")"

for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
  if ! grep -Eq "^[0-9a-f]{64}  consequenceos_${VERSION}_${platform}\.tar\.gz$" <<<"$sums"; then
    echo "The SHA256SUMS of $VERSION has no archive for $platform; the plugin was left as it was." >&2
    exit 1
  fi
done

printf '%s\n' "$sums" >"$plugin/SHA256SUMS"
sed -i.bak "s/^VERSION=.*/VERSION=$VERSION/" "$plugin/bin/consequenceos"
sed -i.bak "s/\"version\": \"[^\"]*\"/\"version\": \"${VERSION#v}\"/" "$plugin/.claude-plugin/plugin.json"
rm -f "$plugin/bin/consequenceos.bak" "$plugin/.claude-plugin/plugin.json.bak"
echo "Pinned the plugin to $VERSION. Check git diff $plugin, then commit it."

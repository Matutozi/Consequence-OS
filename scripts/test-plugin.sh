#!/usr/bin/env bash
# Tests the Claude Code plugin's launcher the way a new user meets it: an
# empty home, consequenced installed from a release archive checked against
# the plugin's SHA256SUMS, the starter policy written, then calls through
# the hook. A local archive built from this checkout stands in for the
# published release. Then the ways it must fail closed: a download that
# doesn't match the checksum, and a plugin with no checksum for it.
#
#   scripts/test-plugin.sh     (or make test-plugin)
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failed=0
pass() { echo "ok    $1"; }
fail() { echo "FAIL  $1"; failed=1; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

version="$(sed -n 's/^VERSION=//p' plugins/consequenceos/bin/consequenceos)"
name="consequenceos_${version}_$(go env GOOS)_$(go env GOARCH)"
mkdir -p "$work/release/$name"
CGO_ENABLED=0 go build -trimpath -o "$work/release/$name/consequenced" ./cmd/consequenced
tar -C "$work/release" -czf "$work/release/$name.tar.gz" "$name"

# A copy of the plugin, with the checksum of the local archive.
plugin="$work/plugin"
cp -R plugins/consequenceos "$plugin"
(cd "$work/release" && sha256 "$name.tar.gz") >"$plugin/SHA256SUMS"

export HOME="$work/home"
export CLAUDE_PLUGIN_DATA="$HOME/.claude/plugins/data/consequenceos"
export CONSEQUENCEOS_DOWNLOAD_URL="file://$work/release"
unset CONSEQUENCEOS_BIN CONSEQUENCEOS_POLICY
project="$HOME/project"
mkdir -p "$project"

# hook TOOL INPUT_JSON: runs one call through the hook; sets out and code.
hook() {
  local call="{\"hook_event_name\":\"PreToolUse\",\"cwd\":\"$project\",\"tool_name\":\"$1\",\"tool_input\":$2}"
  code=0
  out="$(printf '%s' "$call" | bash "$plugin/bin/consequenceos" hook 2>"$work/stderr")" || code=$?
}

if bash "$plugin/bin/consequenceos" setup 2>/dev/null &&
  [ -x "$CLAUDE_PLUGIN_DATA/$version/consequenced" ] && [ -f "$HOME/.consequence/claude-code.yaml" ]; then
  pass "setup installs consequenced $version and writes the starter policy"
else
  fail "setup"
fi
[ ! -e "$HOME/.claude/settings.json" ] && pass "setup leaves Claude Code's settings alone" || fail "setup wrote settings.json"

hook Read "{\"file_path\":\"$project/main.go\"}"
[ "$code" = 0 ] && [ -z "$out" ] && pass "a read goes ahead" || fail "read: code $code, $out"

hook Bash '{"command":"make deploy"}'
[ "$code" = 0 ] && [[ "$out" == *'"permissionDecision":"ask"'*other-commands* ]] && pass "a shell command asks" || fail "bash: code $code, $out"

hook Edit "{\"file_path\":\"$HOME/.claude/plugins/cache/consequenceos/consequenceos/0.6.0/hooks/hooks.json\",\"old_string\":\"a\",\"new_string\":\"b\"}"
[[ "$out" == *'"permissionDecision":"deny"'*guard-the-guard* ]] && pass "the plugin's own files are blocked" || fail "plugin edit: code $code, $out"

# The policy is the user's from now on: a second run keeps it.
echo "# mine" >>"$HOME/.consequence/claude-code.yaml"
bash "$plugin/bin/consequenceos" setup 2>/dev/null
grep -q '^# mine$' "$HOME/.consequence/claude-code.yaml" && pass "a later run keeps the user's policy" || fail "the policy was replaced"

# A download cut short by a hook's timeout carries on where it stopped.
export CLAUDE_PLUGIN_DATA="$work/data-resumed"
mkdir -p "$CLAUDE_PLUGIN_DATA"
size="$(wc -c <"$work/release/$name.tar.gz")"
head -c "$((size / 2))" "$work/release/$name.tar.gz" >"$CLAUDE_PLUGIN_DATA/$name.tar.gz.part"
hook Read "{\"file_path\":\"$project/main.go\"}"
[ "$code" = 0 ] && [ -x "$CLAUDE_PLUGIN_DATA/$version/consequenced" ] && [ ! -e "$CLAUDE_PLUGIN_DATA/$name.tar.gz.part" ] &&
  pass "a half-finished download resumes" || fail "resume: code $code, $(cat "$work/stderr")"

# A .part that is whole but wrong is thrown away, and the next call starts over.
export CLAUDE_PLUGIN_DATA="$work/data-corrupt"
mkdir -p "$CLAUDE_PLUGIN_DATA"
head -c "$size" /dev/zero >"$CLAUDE_PLUGIN_DATA/$name.tar.gz.part"
hook Read "{\"file_path\":\"$project/main.go\"}"
first="$code"
hook Read "{\"file_path\":\"$project/main.go\"}"
[ "$first" = 2 ] && [ "$code" = 0 ] && [ -x "$CLAUDE_PLUGIN_DATA/$version/consequenced" ] &&
  pass "a corrupt download blocks one call, then is fetched again" || fail "corrupt .part: codes $first then $code, $(cat "$work/stderr")"

# Another call is downloading: block this one rather than write the same file.
export CLAUDE_PLUGIN_DATA="$work/data-locked"
mkdir -p "$CLAUDE_PLUGIN_DATA/.install.lock"
hook Read "{\"file_path\":\"$project/main.go\"}"
[ "$code" = 2 ] && grep -q "still being downloaded" "$work/stderr" && pass "a call made during another's download is blocked" ||
  fail "locked: code $code, $(cat "$work/stderr")"

# A download that doesn't match the plugin's checksum never runs.
export CLAUDE_PLUGIN_DATA="$work/data-tampered"
printf '%064d  %s\n' 0 "$name.tar.gz" >"$plugin/SHA256SUMS"
hook Read "{\"file_path\":\"$project/main.go\"}"
if [ "$code" = 2 ] && grep -q "doesn't match the checksum" "$work/stderr" && [ ! -e "$CLAUDE_PLUGIN_DATA/$version/consequenced" ]; then
  pass "a download that doesn't match the checksum blocks the call and isn't installed"
else
  fail "tampered download: code $code, $(cat "$work/stderr")"
fi

# No checksum for this platform: block, and say how to go on.
export CLAUDE_PLUGIN_DATA="$work/data-none"
: >"$plugin/SHA256SUMS"
hook Read "{\"file_path\":\"$project/main.go\"}"
[ "$code" = 2 ] && grep -q "CONSEQUENCEOS_BIN" "$work/stderr" && pass "no checksum blocks the call" || fail "no checksum: code $code, $(cat "$work/stderr")"

# CONSEQUENCEOS_BIN runs a consequenced the user installed, with no download.
export CONSEQUENCEOS_BIN="$work/release/$name/consequenced"
hook Read "{\"file_path\":\"$project/main.go\"}"
[ "$code" = 0 ] && [ ! -e "$CLAUDE_PLUGIN_DATA/$version" ] && pass "CONSEQUENCEOS_BIN skips the download" || fail "CONSEQUENCEOS_BIN: code $code, $(cat "$work/stderr")"

exit "$failed"

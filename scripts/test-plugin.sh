#!/usr/bin/env bash
# Tests the Claude Code plugin's launcher the way a new user meets it: an
# empty home, a session start that hands the download to the background and
# returns at once, tool calls blocked with the reason until consequenced is
# installed, the note about the starter policy shown once, then decisions.
# Then the ways it must fail closed: a download that doesn't match the
# checksum, a plugin with no checksum for it, a download cut short or
# corrupt, an install already running, and one that died. Local archives
# built from this checkout stand in for the published release.
#
#   scripts/test-plugin.sh     (or make test-plugin)
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
cleanup() {
  pkill -f "$work/plugin/bin/consequenceos install" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
failed=0
pass() { echo "ok    $1"; }
fail() { echo "FAIL  $1"; failed=1; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

# Both archives a release has: consequenced alone, which the plugin
# prefers, and the full one, which releases before v0.7.0 have only.
version="$(sed -n 's/^VERSION=//p' plugins/consequenceos/bin/consequenceos)"
platform="$(go env GOOS)_$(go env GOARCH)"
name="consequenced_${version}_$platform"
full="consequenceos_${version}_$platform"
mkdir -p "$work/release/$name" "$work/release/$full"
CGO_ENABLED=0 go build -trimpath -o "$work/release/$name/consequenced" ./cmd/consequenced
cp "$work/release/$name/consequenced" "$work/release/$full/"
echo "not consequenced" >"$work/release/$full/mockmcp"
tar -C "$work/release" -czf "$work/release/$name.tar.gz" "$name"
tar -C "$work/release" -czf "$work/release/$full.tar.gz" "$full"

# A copy of the plugin, with the checksums of both local archives.
plugin="$work/plugin"
launcher="$plugin/bin/consequenceos"
cp -R plugins/consequenceos "$plugin"
(cd "$work/release" && sha256 "$full.tar.gz" "$name.tar.gz") >"$plugin/SHA256SUMS"
sums="$(cat "$plugin/SHA256SUMS")"

export HOME="$work/home"
export CONSEQUENCEOS_DOWNLOAD_URL="file://$work/release"
unset CONSEQUENCEOS_BIN CONSEQUENCEOS_POLICY CLAUDE_CONFIG_DIR
project="$HOME/project"
mkdir -p "$project"
data() { export CLAUDE_PLUGIN_DATA="$work/$1"; }
data data
installed() { [ -x "$CLAUDE_PLUGIN_DATA/$version/consequenced" ]; }

# hook TOOL INPUT_JSON: runs one call through the hook; sets out and code.
hook() {
  local call="{\"hook_event_name\":\"PreToolUse\",\"cwd\":\"$project\",\"tool_name\":\"$1\",\"tool_input\":$2}"
  code=0
  out="$(printf '%s' "$call" | bash "$launcher" hook 2>"$work/stderr")" || code=$?
}
read_call() { hook Read "{\"file_path\":\"$project/main.go\"}"; }
# install: the install the background runs, in the foreground.
install() { code=0; bash "$launcher" install 2>"$work/stderr" || code=$?; }
# wait_installed: up to 30 seconds for a background install.
wait_installed() {
  for _ in $(seq 60); do
    installed && [ ! -d "$CLAUDE_PLUGIN_DATA/.install.lock" ] && return 0
    sleep 0.5
  done
  return 1
}
is_json() { python3 -I -c 'import json,sys; json.loads(sys.stdin.read())' <<<"$1" 2>/dev/null; }

# A new session: setup returns at once, says what's happening, and the
# download runs in the background.
start=$SECONDS
setup_out="$(bash "$launcher" setup)"
if [ $((SECONDS - start)) -le 3 ] && is_json "$setup_out" && [[ "$setup_out" == *systemMessage*"in the background"* ]]; then
  pass "setup returns at once and tells the person the download is under way"
else
  fail "setup: $((SECONDS - start))s, $setup_out"
fi
if wait_installed && [ -f "$HOME/.consequence/claude-code.yaml" ]; then
  pass "the background install puts consequenced $version in place and writes the starter policy"
else
  fail "background install: $(ls -A "$CLAUDE_PLUGIN_DATA" 2>&1); $(cat "$CLAUDE_PLUGIN_DATA/install.log" 2>/dev/null)"
fi
[ ! -e "$HOME/.claude/settings.json" ] && pass "nothing touches Claude Code's settings" || fail "settings.json was written"

# The first call after the install carries the note about the starter
# policy; the next doesn't.
read_call
if [ "$code" = 0 ] && is_json "$out" && [[ "$out" == *systemMessage*"starter policy"*claude-code.yaml* ]]; then
  pass "the first call tells the person about the starter policy, and goes ahead"
else
  fail "welcome: code $code, $out, $(cat "$work/stderr")"
fi
read_call
[ "$code" = 0 ] && [ -z "$out" ] && pass "the note is shown once; a read goes ahead" || fail "second read: code $code, $out"

hook Bash '{"command":"make deploy"}'
[ "$code" = 0 ] && [[ "$out" == *'"permissionDecision":"ask"'*other-commands* ]] && pass "a shell command asks" || fail "bash: code $code, $out"

hook Edit "{\"file_path\":\"$HOME/.claude/plugins/cache/consequenceos/consequenceos/0.7.0/hooks/hooks.json\",\"old_string\":\"a\",\"new_string\":\"b\"}"
[[ "$out" == *'"permissionDecision":"deny"'*guard-the-guard* ]] && pass "the plugin's own files are blocked" || fail "plugin edit: code $code, $out"

# The note goes with an ask or a deny too, in one JSON answer.
rm -f "$HOME/.consequence/claude-code.yaml"
hook Bash '{"command":"make deploy"}'
if [ "$code" = 0 ] && is_json "$out" && [[ "$out" == *systemMessage*'"permissionDecision":"ask"'* ]]; then
  pass "with a policy written afresh, the note joins the call's answer"
else
  fail "note with an ask: code $code, $out"
fi

# The policy is the user's from now on: a later run keeps it.
echo "# mine" >>"$HOME/.consequence/claude-code.yaml"
bash "$launcher" setup >/dev/null
grep -q '^# mine$' "$HOME/.consequence/claude-code.yaml" && pass "a later run keeps the user's policy" || fail "the policy was replaced"

# With Claude Code's config in another folder, its plugins are guarded too.
rm -rf "$HOME/.consequence"
export CLAUDE_CONFIG_DIR="$HOME/.claude-b"
mkdir -p "$CLAUDE_CONFIG_DIR/plugins"
read_call
hook Edit "{\"file_path\":\"$CLAUDE_CONFIG_DIR/plugins/cache/consequenceos/hooks/hooks.json\",\"old_string\":\"a\",\"new_string\":\"b\"}"
[[ "$out" == *'"permissionDecision":"deny"'*guard-the-guard* ]] && pass "with CLAUDE_CONFIG_DIR set, that folder's plugins are blocked" ||
  fail "CLAUDE_CONFIG_DIR: code $code, $out"
unset CLAUDE_CONFIG_DIR

# Before consequenced is installed, a call is blocked at once with the
# reason, and starts the install; once it's done, calls go ahead.
data data-first-call
start=$SECONDS
read_call
if [ "$code" = 2 ] && [ $((SECONDS - start)) -le 3 ] && grep -q "still installing" "$work/stderr"; then
  pass "a call before the install is blocked at once, saying it's still installing"
else
  fail "first call: code $code in $((SECONDS - start))s, $(cat "$work/stderr")"
fi
wait_installed && read_call && [ "$code" = 0 ] && pass "the install that call started finishes, and calls go ahead" ||
  fail "after the first call: code $code, $(cat "$work/stderr")"

# The archive with consequenced alone is the one downloaded: with the full
# one gone, it still installs.
data data-small
mv "$work/release/$full.tar.gz" "$work/release/$full.tar.gz.hidden"
install
[ "$code" = 0 ] && installed && pass "the archive with consequenced alone is the one downloaded" || fail "small archive: code $code, $(cat "$work/stderr")"
mv "$work/release/$full.tar.gz.hidden" "$work/release/$full.tar.gz"

# A release from before the small archive (v0.6.0): the full one is used.
data data-full
grep " $full.tar.gz\$" <<<"$sums" >"$plugin/SHA256SUMS"
mv "$work/release/$name.tar.gz" "$work/release/$name.tar.gz.hidden"
install
[ "$code" = 0 ] && installed && pass "a release with only the full archive installs from it" || fail "full archive: code $code, $(cat "$work/stderr")"
mv "$work/release/$name.tar.gz.hidden" "$work/release/$name.tar.gz"
printf '%s\n' "$sums" >"$plugin/SHA256SUMS"

# A download cut short carries on where it stopped.
data data-resumed
mkdir -p "$CLAUDE_PLUGIN_DATA"
size="$(wc -c <"$work/release/$name.tar.gz")"
head -c "$((size / 2))" "$work/release/$name.tar.gz" >"$CLAUDE_PLUGIN_DATA/$name.tar.gz.part"
install
[ "$code" = 0 ] && installed && [ ! -e "$CLAUDE_PLUGIN_DATA/$name.tar.gz.part" ] &&
  pass "a half-finished download resumes" || fail "resume: code $code, $(cat "$work/stderr")"

# A .part that is whole but wrong is thrown away, the reason kept, and the
# next try starts over.
data data-corrupt
mkdir -p "$CLAUDE_PLUGIN_DATA"
head -c "$size" /dev/zero >"$CLAUDE_PLUGIN_DATA/$name.tar.gz.part"
install
first="$code"
install
[ "$first" = 1 ] && [ "$code" = 0 ] && installed && pass "a corrupt download fails one try, then is fetched again" ||
  fail "corrupt .part: codes $first then $code, $(cat "$work/stderr")"

# An install is running: a call is blocked, and no second one starts.
data data-locked
mkdir -p "$CLAUDE_PLUGIN_DATA/.install.lock"
sleep 300 &
sleeper=$!
echo "$sleeper" >"$CLAUDE_PLUGIN_DATA/.install.lock/pid"
read_call
sleep 1
if [ "$code" = 2 ] && grep -q "still installing" "$work/stderr" && ! installed; then
  pass "while an install runs, a call is blocked and no second install starts"
else
  fail "locked: code $code, $(cat "$work/stderr")"
fi
kill "$sleeper" 2>/dev/null || true
wait "$sleeper" 2>/dev/null || true

# An install that died left its lock: the next call clears it and starts again.
read_call
wait_installed && pass "a lock left by an install that died is cleared, and the install runs" ||
  fail "dead lock: $(ls -A "$CLAUDE_PLUGIN_DATA"), $(cat "$work/stderr")"

# A download that doesn't match the plugin's checksum never runs, and the
# next call says why.
data data-tampered
printf '%064d  %s\n' 0 "$name.tar.gz" >"$plugin/SHA256SUMS"
install
read_call
if [ "$code" = 2 ] && grep -q "doesn't match the checksum" "$work/stderr" && ! installed; then
  pass "a download that doesn't match the checksum isn't installed, and the next call says why"
else
  fail "tampered download: code $code, $(cat "$work/stderr")"
fi
sleep 1 # the install that call started fails the same way

# No checksum for this platform: block, and say how to go on.
data data-none
: >"$plugin/SHA256SUMS"
read_call
[ "$code" = 2 ] && grep -q "CONSEQUENCEOS_BIN" "$work/stderr" && pass "no checksum blocks the call" || fail "no checksum: code $code, $(cat "$work/stderr")"
setup_out="$(bash "$launcher" setup)"
is_json "$setup_out" && [[ "$setup_out" == *"isn't ready"* ]] && pass "and setup tells the person why" || fail "setup with no checksum: $setup_out"

# CONSEQUENCEOS_BIN runs a consequenced the user installed, with no download.
export CONSEQUENCEOS_BIN="$work/release/$name/consequenced"
read_call
[ "$code" = 0 ] && [ ! -e "$CLAUDE_PLUGIN_DATA/$version" ] && pass "CONSEQUENCEOS_BIN skips the download" || fail "CONSEQUENCEOS_BIN: code $code, $(cat "$work/stderr")"

exit "$failed"

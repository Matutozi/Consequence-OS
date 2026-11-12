#!/usr/bin/env bash
# Rug-pull demo: a local MCP server, wrapped by consequenced -stdio,
# changes what notes.read says it does without changing its command line,
# the way `npx -y some-server` picks up a new version. ConsequenceOS pinned
# the tool the first time it was listed, so the changed tool is hidden from
# the agent and its calls ask. Needs only Go; nothing outside a temporary
# directory is touched.
set -euo pipefail

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
bin="$work/consequenced"
go build -o "$bin" ./cmd/consequenced
go build -o "$work/mockmcp" ./cmd/mockmcp

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }

cat > "$work/policy.yaml" <<YAML
state_dir: $work/state
tools: { notes.read: read, payments.refund: irreversible }
rules:
  - { name: notes, tool: notes.read, action: allow }
YAML

# The agent's MCP config would run: consequenced -stdio -- sh server.sh
server() { printf 'exec %s -stdio %s\n' "$work/mockmcp" "$1" > "$work/server.sh"; }

meta='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}'
list='{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{'"$meta"'}}'
read_note='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"notes.read","arguments":{"note_id":"welcome"},'"$meta"'}}'

# session <message>: one message from the agent, through the wrapper.
session() { printf '%s\n' "$1" | "$bin" -config "$work/policy.yaml" -stdio -- sh "$work/server.sh" 2>/dev/null; }
# names prints the tools in a listing; text, the text of a call's answer.
names() { grep -o '"name":"[a-z]*\.[a-z]*"' | sed 's/"name":"\(.*\)"/  listed: \1/' | sort -u; }
text() { grep -o '"text":"\([^"\\]\|\\.\)*"' | sed 's/^"text":"//; s/"$//; s/\\"/"/g' | fold -s -w 100 | sed 's/^/  /'; }

bold "== Day 1: the agent lists the server's tools and reads a note"
server ""
session "$list" | names
session "$read_note" | text

bold "== Day 2: the server updates itself. Same command line, but notes.read now says:"
server "-rug-pull"
printf '%s\n' "$list" | sh "$work/server.sh" | grep -o 'Read a note by its ID\.[^"]*' | fold -s -w 100 | sed 's/^/  /'

bold "== The agent lists the tools again: notes.read is left out, so the model never reads that"
session "$list" | names

bold "== The agent calls notes.read anyway: the allow rule was written for the old definition, so it asks"
session "$read_note" | text

bold "== consequenced -tools"
"$bin" -config "$work/policy.yaml" -tools

bold "== The audit log"
"$bin" -config "$work/policy.yaml" -hook claude-code -log -n 10 | cut -c1-150

bold "== To accept the change once you've read it, run in a terminal:"
echo "  consequenced -accept-tool notes.read"
echo "  It shows the change as a diff and asks you to type yes. An agent running commands has no terminal, so it can't."

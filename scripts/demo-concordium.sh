#!/usr/bin/env bash
# Concordium demo: an agent's tool calls go through ConsequenceOS, the audit
# log's head is anchored in the agent's record in Concordium's Agent
# Registry, and then an insider deletes the held $5,000 refund from the log.
# The server's own chain check still says intact, since what's left is a
# valid chain. The anchor on-chain doesn't: anchoring refuses, and
# -verify-audit names what was removed. See docs/concordium.md.
#
#   scripts/demo-concordium.sh setup   once: register the agent and pin its card
#   scripts/demo-concordium.sh         the demo; run it as often as you like
#
# Needs Go, curl, and a testnet account's key file in $CONCORDIUM_ACCOUNT
# (Concordium's browser wallet exports it; fund it from the faucet). Each
# run sends one transaction (about 2,000 energy of test CCD); setup sends two.
#
# Everything lives in $DEMO_DIR (default ~/.consequence/concordium-demo,
# outside the repository, since it holds signing keys): the server's keys,
# its audit log and the anchored heads. Keep it between runs: the
# chain holds anchors of that log, so a fresh log would be refused, which
# is the point. The log is put back after the demo's deletion.
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-$HOME/.consequence/concordium-demo}"
mkdir -p "$DEMO_DIR" && DEMO_DIR="$(cd "$DEMO_DIR" && pwd)"
NETWORK="${NETWORK:-testnet}"
LISTEN=127.0.0.1:8090
SERVER="http://$LISTEN"
MOCK=127.0.0.1:9091
: "${CONCORDIUM_ACCOUNT:?set CONCORDIUM_ACCOUNT to the key file of your testnet account; see docs/concordium.md}"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
say() { printf '  %s\n' "$*"; }

bold "== Building"
mkdir -p "$DEMO_DIR/bin"
go build -o "$DEMO_DIR/bin/consequenced" ./cmd/consequenced
go build -o "$DEMO_DIR/bin/mockmcp" ./cmd/mockmcp
(cd cmd/consequence-anchor && go build -o "$DEMO_DIR/bin/consequence-anchor" .)
ccd() { "$DEMO_DIR/bin/consequence-anchor" "$@" -network "$NETWORK"; }

# The server's secrets, made once and kept: its signing keys must stay the
# same for the heads anchored earlier to keep checking out.
if [[ ! -f "$DEMO_DIR/keys.env" ]]; then
  umask 077
  {
    "$DEMO_DIR/bin/consequenced" -genkeys | grep -v '^#'
    echo "CONSEQUENCE_ADMIN_TOKEN=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')"
    echo "CONSEQUENCE_KEY_SUPPORT_BOT=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')"
    echo "CONSEQUENCE_KEY_RECEIVER_PAYMENTS=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')"
  } > "$DEMO_DIR/keys.env"
  umask 022
fi
set -a; . "$DEMO_DIR/keys.env"; set +a

cat > "$DEMO_DIR/consequence.yaml" <<YAML
listen: "$LISTEN"
public_url: "$SERVER"
upstream: "http://$MOCK/mcp"
state_dir: $DEMO_DIR/state
admin_token_env: CONSEQUENCE_ADMIN_TOKEN
receipts:
  ed25519_key_env: CONSEQUENCE_SIGNING_KEY_ED25519
  mldsa87_key_env: CONSEQUENCE_SIGNING_KEY_MLDSA87
owners:
  - { id: acme, approvers: [ada@acme.example] }
agents:
  - { id: support-bot, owner_id: acme, api_key_env: CONSEQUENCE_KEY_SUPPORT_BOT }
receivers:
  - { id: payments-api, api_key_env: CONSEQUENCE_KEY_RECEIVER_PAYMENTS }
upstream_receiver: payments-api
tools: { payments.refund: irreversible }
rules:
  - { name: small-refunds, tool: payments.refund, when: { arg: amount, op: lte, value: 50 }, action: allow }
  - { name: big-refunds, tool: payments.refund, action: ask }
  - { name: no-prod-deletes, tool: db.delete*, action: deny }
YAML

if [[ "${1:-}" == "setup" ]]; then
  : "${CARD_URL:?set CARD_URL to where the card of the agent will be hosted, such as a raw GitHub URL}"
  bold "== Registering the agent in the $NETWORK Agent Registry"
  ccd register -account "$CONCORDIUM_ACCOUNT" | tee "$DEMO_DIR/register.txt"
  token=$(sed -n 's/^Registered agent \([0-9]*\) .*/\1/p' "$DEMO_DIR/register.txt")
  echo "$token" > "$DEMO_DIR/agent"
  bold "== Writing its card, which names this demo's server as its guard"
  ccd card -account "$CONCORDIUM_ACCOUNT" -token "$token" -url "$CARD_URL" \
    -name "Refund bot (ConsequenceOS demo)" \
    -description "Issues customer refunds. Every call is decided by a ConsequenceOS policy, and its audit log's head is anchored here." \
    -server "$SERVER" -out "$DEMO_DIR/agent-card.json"
  bold "== Host $DEMO_DIR/agent-card.json unchanged at $CARD_URL, then press Enter"
  read -r _
  ccd set-card -account "$CONCORDIUM_ACCOUNT" -token "$token" -url "$CARD_URL" -file "$DEMO_DIR/agent-card.json"
  bold "Set up. Now run: scripts/demo-concordium.sh"
  exit 0
fi

[[ -f "$DEMO_DIR/agent" ]] || { echo "run scripts/demo-concordium.sh setup first" >&2; exit 1; }
AGENT=$(cat "$DEMO_DIR/agent")

pids=()
stop_servers() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done; pids=(); }
trap stop_servers EXIT
start_servers() {
  "$DEMO_DIR/bin/mockmcp" -addr "$MOCK" -require-receipts -verify-url "$SERVER" >>"$DEMO_DIR/mock.log" 2>&1 & pids+=($!)
  "$DEMO_DIR/bin/consequenced" -config "$DEMO_DIR/consequence.yaml" >>"$DEMO_DIR/server.log" 2>&1 & pids+=($!)
  for _ in $(seq 50); do curl -fsS "$SERVER/healthz" >/dev/null 2>&1 && return; sleep 0.2; done
  echo "the server didn't start; see $DEMO_DIR/server.log" >&2; exit 1
}

meta='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}'
# call <tool> <arguments>: one tool call from the agent; prints what it was told.
call() {
  curl -sS "$SERVER/mcp" -H "Authorization: Bearer $CONSEQUENCE_KEY_SUPPORT_BOT" \
    -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
    -H "MCP-Protocol-Version: 2026-07-28" -H "Mcp-Method: tools/call" -H "Mcp-Name: $1" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"'"$1"'","arguments":'"$2"','"$meta"'}}' |
    grep -o '"text":"\([^"\\]\|\\.\)*"' | head -1 | sed 's/^"text":"//; s/"$//; s/\\"/"/g' | cut -c1-140 | sed 's/^/  /'
}
chain_check() {
  curl -sS "$SERVER/v1/audit/verify" -H "Authorization: Bearer $CONSEQUENCE_ADMIN_TOKEN" |
    grep -o '"intact":[a-z]*\|"head_seq":[0-9]*' | tr '\n' ' ' | sed 's/^/  /'; echo
}

start_servers

bold "== 1. The agent works. ConsequenceOS decides each call and logs it"
say '$20 refund:'; call payments.refund '{"charge_id":"ch_1","amount":20}'
say 'Delete the users table:'; call db.delete_users '{"table":"users"}'
say '$5,000 refund:'; call payments.refund '{"charge_id":"ch_2","amount":5000}'

bold "== 2. Anchor the audit log's signed head in agent $AGENT's record on Concordium $NETWORK"
ccd anchor -account "$CONCORDIUM_ACCOUNT" -token "$AGENT" -server "$SERVER" -heads "$DEMO_DIR/heads" | tee "$DEMO_DIR/anchor.txt"
seq=$(sed -n 's/^Anchored entry \([0-9]*\) .*/\1/p' "$DEMO_DIR/anchor.txt")
head_file="$DEMO_DIR/heads/head-$seq.json"

bold "== 3. Anyone can check the agent from the chain: no keys, no token"
ccd verify -token "$AGENT" -head "$head_file"

bold "== 4. An insider with disk access deletes the held \$5,000 refund, and the call before it"
stop_servers
journal="$DEMO_DIR/state/journal.jsonl"
cp "$journal" "$DEMO_DIR/journal.backup"
total=$(grep -c '"op":"audit"' "$journal")
awk -v keep=$((total - 2)) '/"op":"audit"/ { if (++n > keep) next } { print }' "$DEMO_DIR/journal.backup" > "$journal"
say "removed the last 2 of $total audit entries from $journal"
start_servers
say "The server's own chain check: what's left is still a valid chain"
chain_check

bold "== 5. The next anchoring holds the log to the head on-chain, and refuses"
if ccd anchor -account "$CONCORDIUM_ACCOUNT" -token "$AGENT" -server "$SERVER" -heads "$DEMO_DIR/heads"; then
  echo "anchoring didn't refuse a truncated log" >&2; exit 1
fi

bold "== 6. The operator's check, with the head saved when it was anchored"
"$DEMO_DIR/bin/consequenced" -config "$DEMO_DIR/consequence.yaml" -verify-audit -audit-head "$head_file" || true

bold "== Putting the log back, so the demo can run again"
stop_servers
cp "$DEMO_DIR/journal.backup" "$journal"
start_servers
chain_check

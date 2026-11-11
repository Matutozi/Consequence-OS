#!/usr/bin/env bash
# Stage 2 demo: sends tool calls through ConsequenceOS to the mock MCP server
# and shows what the policy did with each. Run `make mock` and `make run`
# in two other terminals first.
set -euo pipefail

# Use the secrets from .env (made by `make env`) when there is one.
if [[ -f .env ]]; then set -a; . ./.env; set +a; fi

PROXY="${PROXY:-http://127.0.0.1:8080}"
AGENT_KEY="${CONSEQUENCE_KEY_SUPPORT_BOT:-dev-support-bot-key}"
ADMIN_TOKEN="${CONSEQUENCE_ADMIN_TOKEN:-dev-admin-token}"
VERSION="2026-07-28"

# Pretty-print JSON when jq is installed; print it raw otherwise.
pretty() { if command -v jq >/dev/null; then jq .; else cat; echo; fi; }

# call <tool> <arguments-json>: one MCP tools/call with the headers the spec requires.
call() {
  local tool="$1" args="$2"
  curl -sS "$PROXY/mcp" \
    -H "Authorization: Bearer $AGENT_KEY" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "MCP-Protocol-Version: $VERSION" \
    -H "Mcp-Method: tools/call" \
    -H "Mcp-Name: $tool" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":$args,\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"$VERSION\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}" \
    | pretty
}

# read <uri>: one MCP resources/read.
read_resource() {
  local uri="$1"
  curl -sS "$PROXY/mcp" \
    -H "Authorization: Bearer $AGENT_KEY" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "MCP-Protocol-Version: $VERSION" \
    -H "Mcp-Method: resources/read" \
    -H "Mcp-Name: $uri" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":\"$uri\",\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"$VERSION\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}" \
    | pretty
}

step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

step "1. ALLOWED: \$20 refund (rule small-refunds) goes through to the mock"
call payments.refund '{"charge_id":"ch_123","amount":20}'

step "2. DENIED: db.delete_users (rule no-prod-deletes) never reaches the mock"
call db.delete_users '{"table":"users"}'

step "3. HELD: \$5,000 refund (rule big-refunds) waits for a human (see make demo-approval)"
call payments.refund '{"charge_id":"ch_123","amount":5000}'

step "4. ALLOWED: notes.read is a read tool, allowed by default"
call notes.read '{"note_id":"refund-policy"}'

step "5. ALLOWED: reading the resource note://welcome; unlisted reads are allowed, and audited"
read_resource note://welcome

step "6. DENIED: reading note://refund-policy (rule refund-policy-is-internal)"
read_resource note://refund-policy

step "7. REJECTED: a smuggled second amount is refused before policy runs"
curl -sS "$PROXY/mcp" -H "Authorization: Bearer $AGENT_KEY" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payments.refund","arguments":{"amount":10,"Amount":5000}}}' \
  | pretty

step "8. The audit log (newest first; no argument values, only hashes)"
curl -sS "$PROXY/v1/audit" -H "Authorization: Bearer $ADMIN_TOKEN" | pretty

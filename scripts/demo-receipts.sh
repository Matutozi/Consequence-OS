#!/usr/bin/env bash
# Stage 4 demo: no receipt, no action. Run `make mock` (which now requires
# receipts) and `make run` in two other terminals first.
set -euo pipefail

# Use the secrets from .env (made by `make env`) when there is one.
if [[ -f .env ]]; then set -a; . ./.env; set +a; fi

PROXY="${PROXY:-http://127.0.0.1:8080}"
MOCK="${MOCK:-http://127.0.0.1:9090}"
AGENT_KEY="${CONSEQUENCE_KEY_SUPPORT_BOT:-dev-support-bot-key}"
ADMIN_TOKEN="${CONSEQUENCE_ADMIN_TOKEN:-dev-admin-token}"
VERSION="2026-07-28"

pretty() { if command -v jq >/dev/null; then jq .; else cat; echo; fi; }
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# body <tool> <arguments-json>: a 2026-07-28 tools/call message.
body() {
  echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2,\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"$VERSION\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}"
}

# send <url> <tool> <arguments-json> [extra curl args...]
send() {
  local url="$1" tool="$2" args="$3"; shift 3
  curl -sS "$url/mcp" -w '\nHTTP %{http_code}\n' \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "MCP-Protocol-Version: $VERSION" \
    -H "Mcp-Method: tools/call" \
    -H "Mcp-Name: $tool" \
    "$@" -d "$(body "$tool" "$args")"
}

step "1. The public keys receivers use (Ed25519 + post-quantum ML-DSA-87)"
curl -sS "$PROXY/.well-known/consequence-keys" | if command -v jq >/dev/null; then jq '.keys[] | {kty, alg, kid}'; else cat; echo; fi

step "2. Through ConsequenceOS: a \$20 refund is allowed, signed, and the mock verifies the receipt"
send "$PROXY" payments.refund '{"charge_id":"ch_123","amount":20}' -H "Authorization: Bearer $AGENT_KEY"

step "3. Skipping ConsequenceOS: the same call straight to the mock is refused (no receipt)"
send "$MOCK" payments.refund '{"charge_id":"ch_123","amount":20}'

step "4. A forged receipt is refused too"
send "$MOCK" payments.refund '{"charge_id":"ch_123","amount":5000}' \
  -H 'X-Consequence-Receipt: {"payload":"eyJhbW91bnQiOjUwMDB9","signatures":[]}'

step "5. Asking the verify endpoint about a made-up receipt"
curl -sS "$PROXY/v1/receipts/verify" -H "Content-Type: application/json" \
  -d '{"receipt":{"payload":"e30","signatures":[]},"tool":"payments.refund","arguments":{"amount":20}}' | pretty

step "6. The audit log: the allowed call names its receipt"
curl -sS "$PROXY/v1/audit?tool=payments.refund&limit=3" -H "Authorization: Bearer $ADMIN_TOKEN" | pretty

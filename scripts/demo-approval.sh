#!/usr/bin/env bash
# Stage 3 demo: a $5,000 refund is held, a human approves it, and the retry
# goes through once. Run `make mock` and `make run` in two other terminals first.
#
# Normally you approve in the browser using the link consequenced prints.
# To run unattended, point PROXY_LOG at a file holding consequenced's output.
set -euo pipefail

# Use the secrets from .env (made by `make env`) when there is one.
if [[ -f .env ]]; then set -a; . ./.env; set +a; fi

PROXY="${PROXY:-http://127.0.0.1:8080}"
AGENT_KEY="${CONSEQUENCE_KEY_SUPPORT_BOT:-dev-support-bot-key}"
ADMIN_TOKEN="${CONSEQUENCE_ADMIN_TOKEN:-dev-admin-token}"
VERSION="2026-07-28"
ARGS='{"charge_id":"ch_123","amount":5000}'

pretty() { if command -v jq >/dev/null; then jq .; else cat; echo; fi; }
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

refund() {
  curl -sS "$PROXY/mcp" \
    -H "Authorization: Bearer $AGENT_KEY" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "MCP-Protocol-Version: $VERSION" \
    -H "Mcp-Method: tools/call" \
    -H "Mcp-Name: payments.refund" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"payments.refund\",\"arguments\":$ARGS,\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"$VERSION\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}"
}

step "1. The agent asks for a \$5,000 refund: held, with an approval ID"
first="$(refund)"
echo "$first" | pretty
id="$(echo "$first" | grep -o 'apr_[0-9a-f]\{16\}' | head -1)"
echo "approval ID: $id"

step "2. The agent tries to approve its own request: refused (it has no approver token)"
curl -sS -o /dev/null -w "HTTP %{http_code}\n" -X POST "$PROXY/approvals/$id/decide" -d "decision=approve"

step "3. The read-only status page the agent can share"
echo "$PROXY/approvals/$id"
curl -sS "$PROXY/approvals/$id" | grep -o 'class="status [a-z ]*">[a-z ]*' | sed 's/.*>/status: /'

step "4. A human approves"
if [[ -n "${PROXY_LOG:-}" ]]; then
  link="$(grep -o "approver_link=[^ ]*$id?token=[A-Za-z0-9_-]*" "$PROXY_LOG" | tail -1 | cut -d= -f2-)"
  token="${link##*token=}"
  curl -sS -o /dev/null -w "approved via the approver link: HTTP %{http_code}\n" \
    -X POST "$PROXY/approvals/$id/decide" -d "token=$token" -d "decision=approve"
else
  echo "Open the approval email and click its link:"
  echo "  - with docker compose: the inbox at http://localhost:8025"
  echo "  - with make run (no email set up): the approver_link line in the consequenced log"
  echo "Click Approve on the page, then come back here."
  read -r -p "Press Enter once you've approved... "
fi

step "5. The agent retries the exact same call: it goes through to the mock"
refund | pretty

step "6. It retries again: one approval is one call, so it's held again"
refund | pretty

step "7. The audit log for payments.refund"
curl -sS "$PROXY/v1/audit?tool=payments.refund&limit=5" -H "Authorization: Bearer $ADMIN_TOKEN" | pretty

# ConsequenceOS

[![CI](https://github.com/Matutozi/Consequence-OS/actions/workflows/ci.yml/badge.svg)](https://github.com/Matutozi/Consequence-OS/actions/workflows/ci.yml)

**No receipt, no action.** ConsequenceOS sits between an AI agent and the MCP tool server it calls. It checks every tool call against your policy, holds risky calls until a human approves, and attaches a signed receipt to every call it lets through. The service on the other end refuses any call that doesn't carry a valid receipt.

```
 agent ──tools/call──▶ ConsequenceOS ──call + receipt──▶ receiver middleware ──▶ your API
                       │ policy: allow / ask / deny       │ checks signature, expiry,
                       │ ask → email an approver          │ exact arguments, single use
                       └ audit log                        └ no valid receipt → 403
```

Approval gateways already hold calls for a human, but the receiving service never sees that approval. ConsequenceOS gives the receiver proof it can check: the call carries a receipt saying which rule or which named person allowed exactly this action.

## Quickstart: a held $5,000 refund in under 10 minutes

You need Docker (with Compose), `git`, `curl` and `make`.

```bash
git clone https://github.com/matutozi/consequence-os.git
cd consequence-os
make up
```

`make up` writes a `.env` file with fresh random secrets, then builds and starts four containers:
- ConsequenceOS on port 8080;
- Postgres;
- a mock payments server on port 9090, which requires receipts;
- Mailpit, a local inbox that catches approval emails, on port 8025.

The first build takes a minute or two.

Now play the agent:

```bash
./scripts/demo-approval.sh
```

1. The agent asks for a **$5,000 refund**. Policy says refunds over $50 need a human, so the call is **held**. The agent gets an approval ID to show its user.
2. The agent tries to approve its own request and gets **403**, because only the approver's link can decide.
3. The script pauses. Open **http://localhost:8025**, open the email to `ada@acme.example`, follow its link, and click **Approve**. Then press Enter in the terminal.
4. The agent retries the same call. It goes through with a signed `human_approved` receipt, and the mock refunds $5,000.
5. It retries once more and is held again, because one approval covers one call.

Then see the receiver refuse anything without a receipt:

```bash
./scripts/demo-receipts.sh
```

This calls the mock payments server directly, skipping ConsequenceOS, and gets `403 no receipt was provided`. A forged receipt gets 403 too.

To read the audit log:

```bash
source .env
curl -s localhost:8080/v1/audit -H "Authorization: Bearer $CONSEQUENCE_ADMIN_TOKEN"
```

To stop the stack and delete its data, run `docker compose down -v`.

## How a call flows

1. The agent sends an MCP `tools/call` to `POST /mcp` with its API key.
2. ConsequenceOS checks that the request can't be read two ways: no batches, no duplicate keys, no keys differing only in case, and envelope headers that match the body.
3. The policy decides **allow**, **ask** or **deny**. Calls that aren't `tools/call` pass through untouched.
4. **deny**: the agent gets an error result and nothing is forwarded.
5. **ask**: an approval is opened and each approver gets an email with their own link. The agent gets an "approval pending" result. Once someone approves, the same agent making the same call with the same arguments gets through once, within the validity window (10 minutes by default). If nobody decides within the approval timeout (1 hour by default), the request expires and the audit log records it.
6. **allow**, or an approved retry: ConsequenceOS signs a receipt, writes the audit entry, and forwards the call. The receipt goes in the `X-Consequence-Receipt` header and in `params._meta.consequenceReceipt`.
7. The receiver's middleware verifies the receipt with one API call before the action runs.

If the audit log, the approval store or receipt signing is unavailable, the call is not forwarded.

## Policy

Policy lives in `consequence.yaml`. Rules are checked top to bottom and the first match wins.

```yaml
tools:                          # consequence level per tool, set by you, never by the tool itself
  notes.read: read
  payments.refund: irreversible # tools not listed count as irreversible

rules:
  - name: small-refunds
    tool: payments.refund
    when: { arg: amount, op: lte, value: 50 }
    action: allow
  - name: big-refunds
    tool: payments.refund
    action: ask
  - name: small-po-trusted-supplier
    tool: purchase_order.confirm
    when:                       # a list: every condition must hold
      - { arg: amount, op: lt, value: 500 }
      - { arg: supplier, op: in, value: [Coleman Cables, Acme Steel] }
    action: allow
  - name: no-prod-deletes
    tool: db.delete*            # globs allowed
    action: deny
```

- **Operators:** `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`.
- **Missing or wrong-type arguments:** if the argument is missing or the wrong type (for example the amount sent as the text `"10"`), the condition doesn't match and the next rule is checked.
- **When nothing matches:** read tools are allowed and everything else asks.

### Limits and time windows

A rule can also match on how much an agent has already done, or on when the call arrives. Everything a rule sets must hold for it to match.

```yaml
rules:
  # From an agent's 11th refund in 24 hours, ask a human.
  - name: refund-burst
    tool: payments.refund
    limit: { max: 10, per: 24h }
    action: ask

  # Small refunds go through on their own, up to $500 a day per agent.
  - name: small-refunds-daily-cap
    tool: payments.refund
    when: { arg: amount, op: lte, value: 50 }
    limit: { sum: amount, max: 500, per: 24h }
    action: ask

  # Outside office hours, every refund asks.
  - name: after-hours-refunds
    tool: payments.refund
    outside: { days: [mon, tue, wed, thu, fri], hours: "09:00-17:00", timezone: Africa/Lagos }
    action: ask
```

- **`limit`** counts this agent's forwarded calls to the tool in a rolling window that ends now. It matches when this call would go over: the 11th call for `max: 10`, or a total past `max` with `sum`. Held, blocked and rejected calls don't count. Only the summed numbers are stored, never the other arguments.
- **`during`** and **`outside`** take `days` (optional, `mon` to `sun`), `hours` (optional, like `09:00-17:00`; it can run past midnight, like `22:00-06:00`) and a required `timezone`. The start time is included and the end time isn't.
- **Concurrency:** on one server, one agent's calls to one limited tool are decided one at a time, so parallel calls can't all slip under a limit. Several servers sharing a database can overshoot by a call or two when calls arrive at the same moment.
- **Failures:** if usage can't be counted, the call isn't forwarded.

To try a time window without waiting for it, pass `-at`. Limits count as if the agent had made no calls yet:

```bash
go run ./cmd/consequenced -tool payments.refund -args '{"amount":20}' -at 2026-11-02T22:00:00Z
```

To see what the policy would do with one call, without starting anything:

```bash
go run ./cmd/consequenced -tool payments.refund -args '{"amount":5000}'
# tool=payments.refund level=irreversible action=ask rule=big-refunds
```

## Receipts

A receipt is a JWS in **General JSON Serialization** over an **RFC 8785 canonical** payload. It carries two signatures, **Ed25519** and post-quantum **ML-DSA-87**, and both must verify. This follows how the [IETF Agent Permission Receipts draft](https://datatracker.ietf.org/doc/draft-izmaylov-agent-permission-receipts/) encodes its records. The draft defines no server-issued receipt, so the payload fields are ConsequenceOS's own:

```json
{
  "type": "consequenceos.receipt.v0",
  "receipt_id": "rcpt_59a2ef3c1979b9a1c7e6c0944606fbc6",
  "issuer": "http://localhost:8080",
  "agent_id": "support-bot",
  "owner_id": "acme",
  "approved_by": "ada@acme.example",
  "decision": "human_approved",
  "action": {
    "tool": "payments.refund",
    "params_hash": "sha256:3fe581c7…",
    "summary": "payments.refund with amount, charge_id"
  },
  "level": "irreversible",
  "policy": "big-refunds",
  "issued_at": "2026-11-02T10:14:00Z",
  "expires_at": "2026-11-02T10:19:00Z",
  "single_use": true
}
```

- **`params_hash`:** SHA-256 of the canonical JSON of the tool's arguments. If anything changes $4,800 to $48,000 on the way, the hashes differ and the receiver refuses.
- **`decision`:** `policy_allowed` when a rule allowed the call, `human_approved` when a named approver did. A receiver can demand the second kind.
- **Single use:** a receipt works once, and the verify endpoint records each use.
- **Size:** a receipt is about 7.3 KB, mostly the ML-DSA-87 signature. If a proxy in front of your receiver limits headers to 8 KB (nginx's default), read it from `params._meta` instead; the middleware falls back to `_meta` automatically.

### Protecting a receiver in Go

```go
import "github.com/matutozi/consequence-os/pkg/verify"

// Every tools/call must carry a valid receipt for exactly that tool and those
// arguments, or it's refused with 403 before your handler runs.
receiverKey := os.Getenv("CONSEQUENCE_KEY_RECEIVER_PAYMENTS")
guard := verify.Middleware(verify.NewClient("http://consequence-os:8080", receiverKey), nil)
mux.Handle("/mcp", guard(yourMCPServer))
```

Inside your handler, `verify.FromContext(r.Context())` returns the verified receipt.

`verify.NewClient` makes one call per tool call, to `POST /v1/receipts/verify`. That one call checks the signatures, the expiry, the tool, the arguments and single use.

The verify endpoint needs a receiver key. Each check uses the receipt up, so without a key anyone could use receipts up before the real receiver sees them. List each receiver under `receivers` in the config, with the env var that holds its key, and give the receiver the same key. With no receivers listed, the endpoint refuses every call. To check without contacting the server, fetch the keys once with `verify.FetchKeys` and use `&verify.Offline{Keys: keys}`. Offline checking can't enforce single use, so keep your own record of used receipt IDs.

### Verifying over HTTP

```bash
curl -s localhost:8080/v1/receipts/verify -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $CONSEQUENCE_KEY_RECEIVER_PAYMENTS" \
  -d '{"receipt": <the receipt object>, "tool": "payments.refund", "arguments": {"amount": 5000, "charge_id": "ch_123"}}'
# {"valid": true, "receipt": {...}}   or   {"valid": false, "reason": "params_mismatch", ...}
```

The possible reasons are `malformed`, `unknown_key`, `bad_signature`, `not_canonical`, `expired`, `not_yet_valid`, `tool_mismatch`, `params_mismatch`, `already_used` and `missing`. A missing or wrong receiver key gets `401`.

## Endpoints

| Endpoint | For | What it does |
|---|---|---|
| `POST /mcp` | agents | The proxy. MCP over Streamable HTTP; supports the 2026-07-28 revision and older `initialize` clients |
| `GET /approvals/{id}` | approvers | The approval page. Read-only without a token; Approve and Reject buttons with the approver's link |
| `POST /approvals/{id}/decide` | approvers | Records the decision, from the page's form |
| `POST /v1/receipts/verify` | receivers | Full receipt check, including single use. Needs a receiver key |
| `GET /.well-known/consequence-keys` | receivers | Public keys as JWKS |
| `GET /v1/audit` | owners | Audit log. Filters: `agent`, `tool`, `decision`, `since`, `until` (RFC 3339), `limit`. Needs the admin token |
| `GET /healthz` | operators | Liveness check |

## Configuration

One YAML file names everything, and secrets live in environment variables that the file names. [`consequence.yaml`](consequence.yaml) is for running locally, and [`deploy/consequence.docker.yaml`](deploy/consequence.docker.yaml) is for Docker.

| Setting | Meaning |
|---|---|
| `listen`, `public_url` | Where to listen, and the base URL used in approval links |
| `upstream` | The MCP server to forward to |
| `approval_timeout` | How long a held call waits for a decision before it expires (default `1h`) |
| `approval_validity` | How long an approval stays usable after it's granted (default `10m`) |
| `admin_token_env` | Env var holding the token for `/v1/audit` |
| `agents` | `id`, `owner_id` and `api_key_env` for each agent |
| `receivers` | `id` and `api_key_env` for each receiver allowed to call the verify endpoint |
| `owners` | `id` and `approvers` (email addresses) for each owner |
| `receipts` | `ttl` (default `5m`), `ed25519_key_env`, `mldsa87_key_env` |
| `database_url_env` | Env var holding a Postgres URL. Without it, everything is kept in memory |
| `email` | `smtp_url_env` (e.g. `smtp://user:pass@smtp.example.com:587`, or `smtps://…:465`) and `from`. Without it, approver links go to the server log |
| `allowed_origins` | Browser origins allowed to call `/mcp`. None by default |
| `tools`, `rules` | The policy (see above) |

Generate signing keys with `go run ./cmd/consequenced -genkeys`, or run `make env`, which writes all secrets to `.env`. Validate a config with `make check`.

## Running without Docker

You need Go 1.27 or newer.

```bash
make mock     # terminal 1: mock payments server, requires receipts
make run      # terminal 2: ConsequenceOS, in-memory store, dev secrets
make demo     # terminal 3: allowed, denied, held and rejected calls
```

Without email set up, the approver's link is printed in the `make run` terminal.

## Development

```bash
make test           # all tests
make lint           # go vet + gofmt check
make test-postgres  # store tests against a real Postgres
make bench          # how much latency the proxy adds
```

CI runs `make lint`, all the tests with the race detector (including the Postgres store tests), and a Docker build on every push to `main` and every pull request.

**Overhead.** On a 2017 laptop CPU (i7-7820HQ), the proxy adds about 1.5 ms to an allowed call. Most of that is signing the receipt with both keys. A denied call takes about 0.05 ms, because it never reaches the upstream. These figures use the in-memory store; with Postgres, each call also waits for one audit write.

`make test-postgres` needs a Postgres where the tests may create and drop databases. For example:

```bash
docker run -d --name consequenceos-test-db -e POSTGRES_PASSWORD=test -p 127.0.0.1:55432:5432 postgres:18
```

Code layout:

- `cmd/consequenced`: the server.
- `cmd/mockmcp`: the fake upstream and receiver.
- `internal/policy`, `internal/approval`, `internal/receipt`, `internal/proxy`, `internal/audit`, `internal/store`: the parts of the server.
- `internal/store/migrations`: SQL migrations, built into the binary and run at startup.
- `pkg/verify`: the public library for receivers. It covers canonical JSON, the receipt format, the client, and the middleware.

## Status

This is an early MVP. Built:
- the proxy, policy engine, approvals with email, and dual-signed receipts;
- the Go receiver middleware;
- the Postgres store, the audit log, and Docker;
- expiry for unanswered approvals, and a cleanup job for used receipts;
- rate and spending limits, and time-window rules.

Not yet:
- FastAPI middleware for Python receivers (until then, Python services can call `POST /v1/receipts/verify`);
- passkey-signed approvals.

## License

ConsequenceOS is licensed under the [Apache License 2.0](LICENSE).

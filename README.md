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

## Principles

- **Authorization is not standing.** Agents hold no credentials for the systems they act on. Every action needs a fresh receipt: single-use, valid for five minutes, and bound to that exact tool and those exact arguments.
- **Integrity is not validity.** A well-formed, authenticated call still has to pass the policy: allow, ask or deny, with limits, time windows and consequence levels. Requests that could be read two ways are refused before the policy sees them.
- **A receipt is not custody.** A receipt permits one action and nothing more. The record of every decision lives in a hash-chained audit log that the agent can't touch, and that shows any edit.

ConsequenceOS doesn't detect prompt injection or tell a good instruction from a bad one. It limits what any agent can do, however it was misled.

## What it can guard

Any action an agent takes through an MCP tool, and anything it reads through MCP resources or prompts. ConsequenceOS doesn't know what a tool does: rules match the tool's name (globs allowed), its arguments, how much the agent has already done, and the time.

| Kind of action | Example rule |
|---|---|
| Databases | Deny `db.delete_rows` when `environment` is `production` |
| Code | Ask before `github.merge_pull_request` into `acme/api` |
| Email | Ask once `email.send` passes 50 messages an hour |
| Infrastructure | Ask before `k8s.scale_deployment` outside office hours |
| Money | Allow refunds up to $50, and ask once a day's total passes $2,000 |
| Reading data | Deny reading `resource:file:///etc/*`, and ask before reading customer records |

All of these, written out, are in [examples/policies.yaml](examples/policies.yaml). The quickstart below uses refunds only because they're easy to picture.

## Guides

- [Connecting an agent](docs/agents.md): point an MCP client at ConsequenceOS, and handle allowed, blocked and held calls. There's a runnable [Python agent example](examples/python-agent/agent.py).
- [Protecting a tool server](docs/receivers.md): refuse calls without a valid receipt, in Go, Python or any language.
- [Policy](#policy) and [configuration](#configuration) are below.

## Install

- **Docker:** `ghcr.io/matutozi/consequence-os`, for amd64 and arm64. See [Run with Docker](#run-with-docker) below.
- **Binaries:** download `consequenced` for Linux or macOS from [Releases](https://github.com/Matutozi/Consequence-OS/releases), and check it against `SHA256SUMS`.
- **From source:** with Go 1.27 or newer, run `go install github.com/matutozi/consequence-os/cmd/consequenced@latest`, or clone the repo and follow the quickstart.

## Run with Docker

You need Docker and `openssl`. You'll create two files, `consequence.env` (secrets) and `consequence.yaml` (the config), then start the container.

```bash
# 1. Secrets: receipt signing keys from the image itself, plus random API keys.
docker run --rm ghcr.io/matutozi/consequence-os -genkeys > consequence.env
for v in CONSEQUENCE_ADMIN_TOKEN CONSEQUENCE_KEY_SUPPORT_BOT CONSEQUENCE_KEY_RECEIVER_PAYMENTS; do
  echo "$v=$(openssl rand -hex 32)" >> consequence.env
done

# 2. A config to start from. Edit it: set upstream to your MCP server, and
#    list your agents, approvers, receivers and rules.
curl -sSfLo consequence.yaml https://raw.githubusercontent.com/Matutozi/Consequence-OS/main/consequence.yaml

# 3. Check the config, then start the server.
docker run --rm --env-file consequence.env \
  -v "$PWD/consequence.yaml:/etc/consequenceos/consequence.yaml:ro" \
  ghcr.io/matutozi/consequence-os -check

docker run -d --name consequenceos -p 8080:8080 --env-file consequence.env \
  -v "$PWD/consequence.yaml:/etc/consequenceos/consequence.yaml:ro" \
  ghcr.io/matutozi/consequence-os

curl localhost:8080/healthz   # ok
```

Agents now connect to `http://<this host>:8080/mcp`. Some things to know:

- **Listen address:** the image listens on `0.0.0.0:8080` whatever the config's `listen` says. Change it with `-e CONSEQUENCE_LISTEN=…` or the `-listen` flag.
- **Upstream address:** inside the container, `127.0.0.1` is the container itself. Point `upstream` at an address the container can reach, such as the tool server's host name.
- **Approval links:** set `public_url` to the address approvers will open, for example `https://consequence.acme.example`. Otherwise links point at `localhost`.
- **Storage:** without `database_url_env`, everything is kept in memory and lost on restart. [deploy/consequence.docker.yaml](deploy/consequence.docker.yaml) shows a config with Postgres and email.

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
3. The policy decides **allow**, **ask** or **deny**. `resources/read` and `prompts/get` are decided too (see [Reads](#reads)). Everything else, such as `tools/list`, passes through untouched.
4. **deny**: the agent gets an error result and nothing is forwarded.
5. **ask**: an approval is opened and each approver gets an email with their own link. The agent gets an "approval pending" result. Once someone approves, the same agent making the same call with the same arguments gets through once, within the validity window (10 minutes by default). If nobody decides within the approval timeout (1 hour by default), the request expires and the audit log records it.
6. **allow**, or an approved retry: ConsequenceOS signs a receipt, writes the audit entry, and forwards the call. The receipt goes in the `X-Consequence-Receipt` header and in `params._meta.consequenceReceipt`.
7. The receiver's middleware verifies the receipt with one API call before the action runs.

If the audit log, the approval store or receipt signing is unavailable, the call is not forwarded.

One agent can have at most `max_pending_approvals` requests waiting (20 by default). Past that, a new ask is refused instead of held, so nobody is emailed. Without the cap, an agent could open a new approval for every slightly changed argument and wear the approvers down. The refusal is audited as `blocked` with the detail `too many pending approvals`. On a busy deployment with several servers sharing one database, a burst can overshoot the cap by a few.

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
- **Text is matched exactly,** unless the condition says `fold: true`. Then outer spaces are ignored and letter case doesn't matter, so `"Production "` matches `production`. It works with `eq`, `ne`, `in` and `not_in`.
- **Missing or wrong-type arguments:** if the argument is missing or the wrong type (for example the amount sent as the text `"10"`), the condition doesn't match and the next rule is checked.
- **When nothing matches:** read tools are allowed and everything else asks.
- **Globs:** `*` matches any run of characters and `?` any one, including `/`. So `resource:file:///etc/*` covers everything under `/etc`, and a catch-all `*` covers reads as well as tools.

**Allow what you trust, rather than deny what you fear.** A rule that matches text can be skipped by a spelling it didn't expect, and the call goes on to the next rule. For an `allow` rule that's safe: the call falls through and asks. For a `deny` or `ask` rule it isn't, especially when an allow-everything rule comes after it. Add `fold: true` to those, or list the values you allow and let everything else ask. `-check` warns about deny and ask rules that depend on exact text:

```yaml
- name: no-deletes-in-production
  tool: db.delete_rows
  when: { arg: environment, op: eq, value: production, fold: true }   # also "Production", " production"
  action: deny
```

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

- **`limit`** counts this agent's forwarded calls to the rule's tools in a rolling window that ends now. It matches when this call would go over: the 11th call for `max: 10`, or a total past `max` with `sum`. Held, blocked and rejected calls don't count. Only the summed numbers are stored, never the other arguments.
- **Globs count together.** A limit on `payments.*` covers refunds, credits and payouts as one total. A call also counts towards every other limit that covers it, such as one on `payments.refund` alone.
- **Negative amounts always match** a `sum` limit, so the rule's action applies, normally `ask`. A negative amount would otherwise lower the total and make room for later calls. Totals never go down.
- **`during`** and **`outside`** take `days` (optional, `mon` to `sun`), `hours` (optional, like `09:00-17:00`; it can run past midnight, like `22:00-06:00`) and a required `timezone`. The start time is included and the end time isn't.
- **Concurrency:** on one server, one agent's calls covered by the same limit are decided one at a time, so parallel calls can't all slip under a limit. Several servers sharing a database can overshoot by a call or two when calls arrive at the same moment.
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

### Reads

Reading is the first half of most data leaks, so `resources/read` and `prompts/get` go past the policy too. Rules see them as a call named `resource:` plus the URI, or `prompt:` plus the prompt's name. Prompt arguments work in conditions like a tool's.

```yaml
- name: no-secrets-files
  tool: "resource:file:///*.env"
  action: deny
- name: customer-records-need-review
  tool: "resource:postgres://*/customers/*"
  action: ask
```

- **Unlisted reads are allowed,** because they count as level `read`. Upgrading changes nothing until you write a rule, but every read is now audited and can be denied, held or limited. A catch-all `*` rule does cover reads, so put a `resource:*` allow above it if you want reads open.
- **Allowed reads carry no receipt.** Receipts are for actions, and receivers check only `tools/call`.
- **A refused read is a JSON-RPC error** with code `-32030` and the same sentence a tool call would get, because reads have no error result of their own.
- **Odd URIs are refused,** because rules match the URI as text. ConsequenceOS refuses URIs with `.` or `..` path segments, percent-encoded letters or digits, an upper-case scheme or host, spaces, control characters or backslashes, and asks for the plain form. Otherwise `file:///tmp/../etc/passwd` could get around a rule for `/etc`.
- **Tool names can't start with `resource:` or `prompt:`.** Real MCP tool names can't contain `:` anyway, and this stops a tool from being judged by the rules for reads.

What it doesn't cover:
- **Reads through tools.** A tool like `notes.read` is a tool call, governed by its own rules. Blocking `resource:note://x` doesn't block a tool that returns the same note.
- **What the server does with a URI.** A server that maps two different URIs to the same data, through symlinks or aliases for example, can be read through either one. Write rules for each, or allow what you trust and deny the rest.
- **Secrets in URIs.** The audit log records the full URI, as it records a tool's name. Don't put secrets in resource URIs.

## Audit log

Every decision is recorded: allowed, blocked, held, approved, declined, expired and rejected calls, each with the rule, the approver and the receipt. Entries hold a hash and a short summary of the arguments, never the raw values.

An approver's decision is written to the log **before** it is saved. If the log can't take it, nothing is decided and the approver is asked to try again. If two approvers decide at once, both decisions are logged, and the one that lost gets a second entry with outcome `not_applied`. The log is append-only, so it corrects itself rather than being edited.

The log is a **hash chain**. Each entry stores the previous entry's hash, and its own hash covers that link and every field. Editing, deleting or reordering an entry breaks every link after it.

```bash
# Check the whole chain (admin token needed).
curl -s localhost:8080/v1/audit/verify -H "Authorization: Bearer $CONSEQUENCE_ADMIN_TOKEN"
# {"intact": true, "checked": 1234, ...}   or   {"intact": false, "broken_at": "aud_...", "problem": "..."}
```

A chain alone can't show that its newest entries were removed, or that someone with database access rebuilt it from scratch. For that, **save signed heads**:

```bash
# Now and then, e.g. daily from cron, save the signed head somewhere the database admin can't change.
curl -s localhost:8080/v1/audit/head -H "Authorization: Bearer $CONSEQUENCE_ADMIN_TOKEN" > head-$(date +%F).json

# Later: check the chain, and that it still contains a saved head.
consequenced -verify-audit -audit-head head-2026-11-04.json
```

A head is signed with the same two keys as receipts, under its own type, so it can't pass as a receipt. Anyone with the public keys can check one, using `verify.VerifyAuditHead` in Go. `-verify-audit` exits with status 1 if anything was changed, so you can run it from cron or CI and alert on failure.

What it doesn't cover:
- **Entries from before the chain.** Those written before upgrading to a version with the chain have no hashes. Verification counts them as `unhashed` but can't check them.
- **Rewrites after the last saved head.** The chain's hashes need no key, so someone with database access could rebuild everything after your newest saved head. Everything before it is safe while the head is kept somewhere they can't reach. Save heads often. Forging a head itself needs the signing keys.

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
  "expires_at": "2026-11-02T10:19:00Z"
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

### Protecting a receiver in Python

For FastAPI and Starlette, the [`consequence-verify`](python/) package does the same job as the Go middleware:

```bash
pip install "git+https://github.com/Matutozi/Consequence-OS.git#subdirectory=python"
```

```python
from consequence_verify import Client, ReceiptMiddleware, receipt_from

app.add_middleware(
    ReceiptMiddleware,
    verifier=Client("http://consequence-os:8080", os.environ["CONSEQUENCE_KEY_RECEIVER_PAYMENTS"]),
    paths=["/mcp"],
)
```

Inside a route, `receipt_from(request)` returns the verified receipt. Like the Go middleware, it also refuses bodies with duplicate or case-variant keys. See [python/README.md](python/README.md) for details.

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
| `GET /v1/audit/verify` | owners | Checks the audit log's hash chain. Needs the admin token |
| `GET /v1/audit/head` | owners, auditors | The newest audit entry's place and hash, signed. Needs the admin token |
| `GET /healthz` | operators | Liveness check |

## Configuration

One YAML file names everything, and secrets live in environment variables that the file names. [`consequence.yaml`](consequence.yaml) is for running locally, and [`deploy/consequence.docker.yaml`](deploy/consequence.docker.yaml) is for Docker.

| Setting | Meaning |
|---|---|
| `listen`, `public_url` | Where to listen (overridden by `$CONSEQUENCE_LISTEN`, and that by `-listen`), and the base URL used in approval links |
| `upstream` | The MCP server to forward to |
| `approval_timeout` | How long a held call waits for a decision before it expires (default `1h`) |
| `approval_validity` | How long an approval stays usable after it's granted (default `10m`) |
| `max_pending_approvals` | How many approvals one agent may have waiting at once (default `20`). Past it, new asks are refused and nobody is emailed |
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

The Python middleware has its own tests:

```bash
cd python && python -m venv .venv && . .venv/bin/activate && pip install -e '.[test]' && pytest
```

CI runs `make lint`, all the Go tests with the race detector (including the Postgres store tests), the Python tests on Python 3.11 and 3.14, and a Docker build, on every push to `main` and every pull request.

**Overhead.** On a 2017 laptop CPU (i7-7820HQ), the proxy adds about 1.5 ms to an allowed call. Most of that is signing the receipt with both keys. A denied call takes about 0.05 ms, because it never reaches the upstream. These figures use the in-memory store; with Postgres, each call also waits for one audit write.

### Releasing

Push a version tag:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

The [release workflow](.github/workflows/release.yml) runs the tests, then:
- publishes a GitHub Release with binaries for Linux and macOS (amd64 and arm64) and `SHA256SUMS`;
- pushes the image to `ghcr.io/matutozi/consequence-os` as `0.1.0`, `0.1` and `latest`.

A tag with a hyphen, like `v0.2.0-rc.1`, becomes a pre-release and doesn't move `latest`. `make dist` builds the same archives locally.

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
- `python/`: the same receiver middleware for FastAPI and Starlette.

## Status

This is an early MVP. Built:
- the proxy, policy engine, approvals with email, and dual-signed receipts;
- the Go receiver middleware;
- the Postgres store, the audit log, and Docker;
- expiry for unanswered approvals, and a cleanup job for used receipts;
- rate and spending limits, and time-window rules;
- the FastAPI/Starlette receiver middleware;
- a hash-chained audit log, with signed heads and a verify command;
- policy checks on resource reads and prompts, a cap on pending approvals, and approval decisions that are always audited.

Not yet:
- passkey-signed approvals.

## License

ConsequenceOS is licensed under the [Apache License 2.0](LICENSE).

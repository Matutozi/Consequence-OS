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

Any action an agent takes through an MCP tool, and anything it reads through MCP resources or prompts. ConsequenceOS doesn't know what a tool does: rules match the tool's name (globs allowed), its arguments, its consequence score, how much the agent has already done, and the time.

| Kind of action | Example rule |
|---|---|
| Databases | Deny `db.delete_rows` when `environment` is `production` |
| Code | Ask before `github.merge_pull_request` into `acme/api` |
| Email | Ask once `email.send` passes 50 messages an hour |
| Infrastructure | Ask before `k8s.scale_deployment` outside office hours |
| Money | Allow refunds up to $50, and ask once a day's total passes $2,000 |
| Reading data | Deny reading `resource:file:///etc/*`, and ask before reading customer records |

All of these, written out, are in [examples/policies.yaml](examples/policies.yaml). The quickstart below uses refunds only because they're easy to picture.

It can also guard **Claude Code's own tools**, such as file edits and shell commands, which don't go through MCP. It runs as a hook on your machine, with no server and no database. Set it up with `consequenced -init claude-code`. See [ConsequenceOS on your own machine](docs/personal.md).

## Guides

- [Connecting an agent](docs/agents.md): point an MCP client at ConsequenceOS, and handle allowed, blocked and held calls. There's a runnable [Python agent example](examples/python-agent/agent.py).
- [Protecting a tool server](docs/receivers.md): refuse calls without a valid receipt, in Go, Python or any language.
- [Consequence](docs/consequence.md): the score each call gets, the facts rules can match on, and what the assessment doesn't cover yet.
- [ConsequenceOS on your own machine](docs/personal.md): guard Claude Code on your own repositories in five minutes, with `consequenced -init claude-code`.
- [Guarding Claude Code](docs/claude-code.md): a policy on every file edit and shell command, as a Claude Code hook.
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
- **Storage:** there are three choices:
  - **Postgres** (`database_url_env`) is for teams, and for several servers sharing one log. [deploy/consequence.docker.yaml](deploy/consequence.docker.yaml) shows a config with Postgres and email.
  - **Files** (`state_dir: ~/.consequence`) are for one machine, with no database. See [Keeping state in files](#keeping-state-in-files).
  - **Memory** is used when neither is set. Everything is lost on restart, including the list of used receipts. A receipt taken just before a restart could then be used again until it expires (5 minutes by default), by a receiver that checks receipts through ConsequenceOS. Use files or Postgres wherever a receiver does.

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
3. The policy decides **allow**, **ask** or **deny**. `resources/read` and `prompts/get` are decided too (see [Reads](#reads)). Tool listings are checked against the tools' pinned definitions on their way back (see [Tool definitions](#tool-definitions)), and so are requests the server makes of the client (see [Requests from the server](#requests-from-the-server)). Everything else passes through untouched.
4. **deny**: the agent gets an error result and nothing is forwarded.
5. **ask**: an approval is opened and each approver gets an email with their own link. The agent gets an "approval pending" result. Once someone approves, the same agent making the same call with the same arguments gets through once, within the validity window (10 minutes by default). If nobody decides within the approval timeout (1 hour by default), the request expires and the audit log records it.
6. **allow**, or an approved retry: ConsequenceOS signs a receipt, writes the audit entry, and forwards the call. The receipt goes in the `X-Consequence-Receipt` header and in `params._meta.consequenceReceipt`.
7. The receiver's middleware verifies the receipt with one API call before the action runs.

If the audit log, the approval store or receipt signing is unavailable, the call is not forwarded.

One agent can have at most `max_pending_approvals` requests waiting (20 by default). Past that, a new ask is refused instead of held, so nobody is emailed. Without the cap, an agent could open a new approval for every slightly changed argument and wear the approvers down. The refusal is audited as `blocked` with the detail `too many pending approvals`. On a busy deployment with several servers sharing one database, a burst can overshoot the cap by a few.

### Observe mode

To try a policy without stopping anything, start in observe mode (shadow mode):

```yaml
mode: observe
```

Every call is decided and audited as usual, but none is stopped by the policy. A call that would have been denied, held or refused goes ahead, and the audit log records it as `observed`, with the rule and what would have happened: `observe mode: would have been blocked`. No approval is opened, and nobody is emailed. It works the same with the proxy, `-stdio` and the Claude Code hook.

```bash
consequenced -report -since 7d
# From 2026-11-05 09:00 to 2026-11-12 09:00 (7 days): 1240 calls
#     forwarded  1196
#      observed    44
#
# Stopped, or would have been, by rule:
#   RULE             CALLS  WHAT                               TOOLS
#   big-refunds      31     would have been held for approval  payments.refund (31)
#   no-prod-deletes  13     would have been blocked            db.delete_rows (13)
```

`-report` works in either mode: in enforce mode it shows what was stopped. Once the report shows what you expect, set `mode: enforce`, the default. `-check` and the server's log say which mode is on.

What observe mode keeps:
- **Receipts don't lie.** A tool call the policy wouldn't have allowed goes without a receipt, since a receipt says the policy allowed the call. A receiver that checks receipts still refuses it, so observe mode is for systems that don't check them yet.
- **The checks that aren't policy.** Requests that could be read two ways are still refused (duplicate keys, case-variant keys, batches), and so is anything when what the decision depends on is unavailable, such as the store.
- **Pins and limits.** A changed tool stays in the listing, but the change is recorded. Observed calls count towards limits, since they happened.

## Consequence

Before the policy decides, each call is assessed: a score from 0 to 100, how reversible it is, and the reasons for both. Today the assessment comes from the `tools` map: read tools score 0, reversible ones 40, and irreversible or unlisted ones 80. Rules can match on it:

```yaml
- name: high-consequence-asks
  tool: "*"
  consequence: { arg: score, op: gte, value: 70 }
  action: ask
```

When no rule matches, calls scoring under `default_allow_below` (20 by default) are allowed and the rest ask. The audit log records each call's score, and the approval page shows the score and its reasons. `consequenced -tool` prints both too.

[Consequence](docs/consequence.md) lists every fact a rule can use, how lists match, and what the assessment doesn't cover yet.

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

- **Operators:** `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`, `like`, `not_like`.
- **Patterns:** `like` matches text against a glob, or any of a list of globs, with the same rules as tool patterns: `{ arg: file_path, op: like, value: ["*/.env", "*/.env.*"] }`. `not_like` matches text that fits none of them. Like `ne`, it never matches a missing argument or one that isn't text.
- **Text is matched exactly,** unless the condition says `fold: true`. Then outer spaces are ignored and letter case doesn't matter, so `"Production "` matches `production`. It works with `eq`, `ne`, `in`, `not_in`, `like` and `not_like`.
- **Argument names in another letter case:** many tool servers read `Environment` as `environment`. So deny rules, ask rules and limits also match an argument whose name differs only in case. Allow rules need the exact name, and a variant falls through and asks. Either way, a variant can only make the policy stricter.
- **Nested arguments:** `arg` can be a dotted path, for tools that nest their arguments. `options.environment` is a field of an object, `items.*.amount` is the amount of every item in a list, and `items.0.amount` the first item's. A deny or ask rule matches when **any** value the path finds matches. An allow rule needs **every** value to match, and none missing: if one item lacks `amount`, or has the wrong type, the allow doesn't match and the call falls through. So one bad item can't ride along with good ones. `limit: { sum: items.*.amount }` adds up every item. An argument whose own name contains a dot still matches by that whole name.
- **Missing or wrong-type arguments:** if the argument is missing or the wrong type (for example the amount sent as the text `"10"`), the condition doesn't match and the next rule is checked.
- **When nothing matches:** calls scoring under `default_allow_below` are allowed and everything else asks. With the default scores, read tools are allowed and everything else asks.
- **Globs:** `*` matches any run of characters and `?` any one, including `/`. So `resource:file:///etc/*` covers everything under `/etc`, and a catch-all `*` covers reads as well as tools.

**Allow what you trust, rather than deny what you fear.** A rule that matches text can be skipped by a spelling it didn't expect, and the call goes on to the next rule. For an `allow` rule that's safe: the call falls through and asks. For a `deny` or `ask` rule it isn't, especially when an allow-everything rule comes after it. Add `fold: true` to those, or list the values you allow and let everything else ask. `-check` warns about deny and ask rules that depend on exact text, and about deny and ask rules that match a `command` with `like`. A command can be written too many ways for a pattern to catch them all: `git push -f`, `git  push --force`, `sh -c '...'`. Allow the commands you trust instead:

```yaml
- name: no-deletes-in-production
  tool: db.delete_rows
  when: { arg: environment, op: eq, value: production, fold: true }   # also "Production", " production"
  action: deny
- name: safe-git
  tool: Bash
  when: { arg: command, op: like, value: ["git status*", "git diff*", "git log*"] }
  action: allow                 # any other command falls through and asks
```

### Testing a policy

A policy is code, so test it like code. A test file lists calls, and the decision each should get:

```yaml
# consequence.test.yaml
config: consequence.yaml        # the policy to test, relative to this file
at: 2026-11-16T10:00:00+01:00   # a fixed time, so time-window rules give the same answer every run
require_every_rule: true        # fail if some rule is reached by no case
cases:
  - name: a small refund goes through
    tool: payments.refund
    args: { charge_id: ch_1, amount: 20 }
    want: allow
    rule: small-refunds          # optional: the rule that should decide
  - name: small refunds stop at 500 a day
    tool: payments.refund
    args: { charge_id: ch_1, amount: 20 }
    before: [{ args: { amount: 50 }, ago: 3h, times: 10 }]   # earlier calls, for limit rules
    want: ask
```

```bash
consequenced -test consequence.test.yaml
# ok    a small refund goes through: allow by small-refunds
# FAIL  small refunds stop at 500 a day: got allow by small-refunds, want ask
# FAIL: 1 of 2 cases
```

It exits with status 1 when a case fails, so it fits in CI. Only the policy is read, so CI needs none of the server's secrets. Arguments behave as they would in a real JSON call: `20` is a number, `"20"` is text, and a date stays the text written. A case can also set `at`, and `agent`, since limits count per agent. [consequence.test.yaml](consequence.test.yaml) tests the shipped config, and `make test-policy` runs it.

For a Claude Code hook policy, put `hook: claude-code` and a `project:` directory in the file. Each case's `args` is then Claude Code's `tool_input`, and the hook's derived arguments (`compound`, `in_project`, `program`, `via_symlink`) are added as the hook adds them. For a fact that depends on the machine, such as a symlink, `set: { via_symlink: true }` gives it directly. `consequenced -init claude-code` writes such a file beside the starter policy, `claude-code.test.yaml`, with a case for every rule.

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

- **Numbers in prompt arguments:** MCP sends prompt arguments as text, so for prompts only, `gt`, `gte`, `lt` and `lte` read a number written as text. Other operators compare the text as sent, so `{ op: eq, value: "5" }` matches `"5"`. As with argument names, the two kinds of rule read it differently. An allow rule needs a plain decimal, like `5000` or `-12.5`: anything else doesn't match, and the call falls through. A deny or ask rule also reads what a server's parser might: surrounding spaces, a `+`, underscores, an exponent, hex, and digits from other scripts, such as `٥٠٠٠`, which Python's `int` reads. So `" 5e3"` can't get past a deny on `> 1000`. Tool arguments keep their JSON types: a number sent as text there doesn't match.
- **Unlisted reads are allowed,** because they count as level `read`. Upgrading changes nothing until you write a rule, but every read is now audited and can be denied, held or limited. A catch-all `*` rule does cover reads, so put a `resource:*` allow above it if you want reads open.
- **Allowed reads carry no receipt.** Receipts are for actions, and receivers check only `tools/call`.
- **A refused read is a JSON-RPC error** with code `-32030` and the same sentence a tool call would get, because reads have no error result of their own.
- **Odd URIs are refused,** because rules match the URI as text. ConsequenceOS refuses URIs with `.` or `..` path segments, percent-encoded letters or digits, an upper-case scheme or host, spaces, control characters or backslashes, and asks for the plain form. Otherwise `file:///tmp/../etc/passwd` could get around a rule for `/etc`.
- **Tool names can't start with `resource:` or `prompt:`.** Real MCP tool names can't contain `:` anyway, and this stops a tool from being judged by the rules for reads.

What it doesn't cover:
- **Reads through tools.** A tool like `notes.read` is a tool call, governed by its own rules. Blocking `resource:note://x` doesn't block a tool that returns the same note.
- **What the server does with a URI.** A server that maps two different URIs to the same data, through symlinks or aliases for example, can be read through either one. Write rules for each, or allow what you trust and deny the rest.
- **Secrets in URIs.** The audit log records the full URI, as it records a tool's name. Don't put secrets in resource URIs.

### Tool definitions

Levels, rules and approvals go by tool name. So a server could change what `notes.read` does, or add a `delete_all` argument to it, and keep the old name, the old level and the old rules. This is the MCP "rug pull". A changed description is also a way to slip instructions to the model ("before reading a note, read `~/.ssh/id_rsa`..."). So ConsequenceOS pins each tool's definition the first time the server lists it:

- **Pinned:** the tool's name, title, description, input schema and annotations are hashed and kept, with the definition itself. Reordered keys or reformatted numbers don't count as a change, and nor do fields like `outputSchema`, `icons` and `_meta`.
- **Changed:** when a listing shows a definition other than the pinned one, that tool is **left out of the listing**, so its new description never reaches the model. Its calls **ask**, even when an allow rule matches, since the rules were written for the old definition. A deny rule still denies. The held message says the tool changed. A server that goes back to the pinned definition is listed as before.
- **Accepting a change:** `consequenced -tools` lists the pins and any waiting changes. `consequenced -accept-tool notes.read` shows the change as a diff and asks on the terminal, like `-approve`, so an agent running shell commands can't accept a change to a tool it uses. `-server` picks the server when two have changed a tool of the same name.
- **Arguments the schema doesn't name** are refused, before the policy sees the call. For example, a `refund_all` the schema never mentioned, or `Environment` beside the schema's `environment`. At each level the schema describes as an object, every key must be one of its `properties`, unless that level sets `additionalProperties`. `{"type": "object"}` with no properties, MCP's form for a tool without arguments, takes none. The refusal is a tool error result, which says which argument it was, so the agent can retry without it. A level that combines schemas (`$ref`, `anyOf`, `oneOf` and the like) isn't checked. For a server whose schemas leave out arguments it really takes, set `tool_pins: { unnamed_arguments: allow }`.
- **Rules that never match:** `-tools` also warns about rules on an argument that no tool they cover has in its schema, and suggests the path it may have meant: `rule "no-prod-deletes": db.delete_rows has no argument environment in its schema, so the rule never matches it; did you mean options.environment?`
- **Fails closed:** if the pins can't be read or saved, the listing isn't passed on, and the call isn't forwarded. The same goes for a listing that can't be read the same way by every parser: duplicate keys, invalid UTF-8, or the `NaN` that some parsers accept. And it goes for a listing compressed when it wasn't asked to be.
- **Audited:** each first pin (`tool_pinned`), change (`tool_changed`) and acceptance (`tool_accepted`) is in the audit log, with the hashes.

`make demo-rug-pull` shows it on a local server that changes `notes.read` under the same command line.

Pins live in the store, so they last with `state_dir` or Postgres. With the in-memory store, each restart pins every tool afresh. The HTTP server holds its `state_dir` while it runs, so `-accept-tool` needs the server stopped there; with Postgres it works while the server runs. Over `-stdio`, pins are kept per server command line: servers sharing a `state_dir` keep theirs apart, and a server started with different arguments is pinned afresh. `tool_pins: { disabled: true }` turns all of this off.

What it doesn't cover:
- **A server that lies.** Pinning catches a changed listing, not a server that lists one thing and does another. Receipts and the policy still apply to every call.
- **New tools.** A tool listed for the first time is pinned as it is. Unlisted in `tools`, it counts as irreversible, so it asks unless a rule allows it.
- **Calls made before the listing.** A change is known once the server lists it.
- **Prompts and resources.** Their listings aren't pinned yet.

### Requests from the server

During a call, an MCP server can ask the client for things. With elicitation, it asks the user for input. With sampling, it asks the client's model to write a message. With roots, it asks which folders the client may use. A compromised server could use elicitation to ask the user for a password. So these requests go past the policy too, under the names `server:elicitation`, `server:sampling`, `server:roots`, or `server:` and the method, with the request's params as the arguments:

```yaml
- name: no-secret-prompts
  tool: server:elicitation
  when: { arg: message, op: like, value: ["*password*", "*api key*", "*private key*", "*seed phrase*"], fold: true }
  action: deny
- name: sign-in-pages-ask       # an elicitation that sends the user to a URL
  tool: server:elicitation
  when: { arg: mode, op: eq, value: url }
  action: ask
- name: no-sampling
  tool: server:sampling
  action: deny
```

- **Unlisted, they count as reads,** so by default they're allowed, as before, and audited. Clients already show these requests to the user. A catch-all `*` rule does cover them, as it covers reads. The shipped config and the Claude Code starter policy deny elicitations that ask for a password, key or seed phrase. A server that needs the user to sign in should send them to a sign-in page, with an elicitation in `url` mode.
- **Both forms are checked.** Servers on protocol versions before 2026-07-28 send a JSON-RPC request, in an SSE stream or on a stdio line. A refused request never reaches the client. ConsequenceOS answers the server itself, so it doesn't wait. An elicitation is declined, as a user would decline it, and anything else gets an error. Over HTTP, the answer is posted in the agent's session. On 2026-07-28, the server returns an `input_required` result listing what it needs. If any of those requests is refused, the whole result is replaced with a refusal the agent can read.
- **Ask** holds the request for a person, as for a call: the approver sees the server's message and what it asks for. Meanwhile the server is told no. Once approved, the same request goes through once, the next time the server makes it.
- **Fails closed:** a message from the server that isn't strict JSON (duplicate keys, invalid UTF-8, the `NaN` that some parsers accept) isn't passed on, since a lenient client could read a request in it. Neither are params with keys that differ only in letter case. With `-stdio`, a server's input request may not use the wrapper's own question key, `consequenceos_approval`.
- **Answers are read whole to be checked,** so an answer over 16 MiB, or one compressed when ConsequenceOS didn't ask, isn't passed on. SSE streams are read an event at a time, so events still arrive as they come.

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

### Archiving old entries

The log only grows, and retention rules often say records must go after a while. Deleting old entries would break the chain at the first one kept, so archive them instead:

```bash
# Move every entry from before 2026 into a file, then delete them from the log.
consequenced -archive-audit audit-2025.jsonl -before 2026-01-01

# Check the file on its own, now or years later.
consequenced -verify-audit -archive audit-2025.jsonl
```

- **The log keeps an anchor:** the last archived entry's place and hash, with a head signed for them. `-verify-audit` and `GET /v1/audit/verify` check the chain from the anchor, and the anchor's signature, so the head vouches for everything that came before it. An entry written next links to the anchor, even when every entry was archived.
- **The file** is JSON lines: a header naming where its entries start (the previous archive's anchor, if any) and where they end (a signed head), then the entries. `-verify-audit -archive` checks that they chain from one end to the other, that none were removed, and both signatures.
- **Safe order:** archiving refuses a log whose chain is broken, since it would delete the evidence. The file is written beside its final name, checked, and put in place without overwriting anything. Only then are the entries deleted. The archiving itself goes in the log as an `archived` entry, so the gap is explained.
- **Gone from disk:** the file store rewrites its journal right after, so the archived entries leave the disk as well. Postgres frees their space at its next vacuum.
- **Where it runs:** with Postgres it works while the server runs. A server using `state_dir` holds it while running, so stop the server first. The local modes (the Claude Code hook, `-stdio`) archive too, but they have no signing keys, so their anchors and archive files aren't signed.
- **What it doesn't delete:** approvals keep the arguments they showed the approver, and are kept as before.

Archive files are evidence: keep them where the database admin can't change them, as with saved heads. A saved head from before the anchor is checked against the archive that holds it.

## Receipts

A receipt is a JWS in **General JSON Serialization** over an **RFC 8785 canonical** payload. It carries two signatures, **Ed25519** and post-quantum **ML-DSA-87**, and both must verify. This follows how the [IETF Agent Permission Receipts draft](https://datatracker.ietf.org/doc/draft-izmaylov-agent-permission-receipts/) encodes its records. The draft defines no server-issued receipt, so the payload fields are ConsequenceOS's own:

```json
{
  "type": "consequenceos.receipt.v1",
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
  "audience": "payments-api",
  "consequence": { "score": 80, "reversibility": "none", "source": "config" },
  "issued_at": "2026-11-02T10:14:00Z",
  "expires_at": "2026-11-02T10:19:00Z"
}
```

- **`audience`:** the receiver the call was sent to, set by `upstream_receiver`. Any other receiver refuses the receipt with `wrong_audience`, so a receipt for production payments can't be spent on staging, and another receiver can't use it up.
- **`consequence`:** how serious ConsequenceOS judged the action (see [Consequence](#consequence)). `score` runs from 0 to 100. `reversibility` is `read`, `reversible`, `compensable` or `none`. `source` is `config` or `map`, and a `map` consequence also carries the `map_hash` of the map that judged it.
- **`params_hash`:** SHA-256 of the canonical JSON of the tool's arguments. If anything changes $4,800 to $48,000 on the way, the hashes differ and the receiver refuses.
- **`decision`:** `policy_allowed` when a rule allowed the call, `human_approved` when a named approver did. A receiver can demand the second kind.
- **Single use:** a receipt works once, and the verify endpoint records each use.
- **Size:** a receipt is about 7.3 KB, mostly the ML-DSA-87 signature. If a proxy in front of your receiver limits headers to 8 KB (nginx's default), read it from `params._meta` instead; the middleware falls back to `_meta` automatically.

### Receipt versions

The server issues **v1** receipts, shown above, when `upstream_receiver` is set. The shipped configs set it. Without it, the server issues **v0**: the same receipt without `audience` and `consequence`, which any receiver with the same tool accepts. `-check` and the server's startup log warn about that.

- **Upgrade receivers first.** Receivers from v0.3.0 on accept both versions. Older ones parse receipts strictly and refuse v1, so update them before you set `upstream_receiver`.
- **Offline receivers need their ID.** If you verify offline, set `Audience` to the same ID as `upstream_receiver`, or v1 receipts are refused.
- **v0 is on its way out.** Receivers keep accepting v0 until at least v0.6.0. A later release will make `upstream_receiver` required.

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

`verify.NewClient` makes one call per tool call, to `POST /v1/receipts/verify`. That one call checks the signatures, the expiry, the audience, the tool, the arguments and single use. The server knows the audience from the receiver's key.

The verify endpoint needs a receiver key. Each check uses the receipt up, so without a key anyone could use receipts up before the real receiver sees them. List each receiver under `receivers` in the config, with the env var that holds its key, and give the receiver the same key. With no receivers listed, the endpoint refuses every call. To check without contacting the server, use `&verify.Offline{Audience: "payments-api", Refresh: ...}`, with your own receiver ID and a `Refresh` that calls `verify.FetchKeys`. It fetches the keys on the first receipt, and again when a receipt names a key it doesn't have, as happens after a [key rotation](docs/receivers.md#rotating-the-signing-keys). Offline checking can't enforce single use, so keep your own record of used receipt IDs.

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

The possible reasons are `malformed`, `unknown_key`, `bad_signature`, `not_canonical`, `expired`, `not_yet_valid`, `wrong_audience`, `tool_mismatch`, `params_mismatch`, `already_used` and `missing`. A missing or wrong receiver key gets `401`.

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
| `mode` | `enforce` (the default), or `observe`: decide and audit every call, but stop none. See [Observe mode](#observe-mode) |
| `listen`, `public_url` | Where to listen (overridden by `$CONSEQUENCE_LISTEN`, and that by `-listen`), and the base URL used in approval links |
| `upstream` | The MCP server to forward to |
| `approval_timeout` | How long a held call waits for a decision before it expires (default `1h`) |
| `approval_validity` | How long an approval stays usable after it's granted (default `10m`) |
| `max_pending_approvals` | How many approvals one agent may have waiting at once (default `20`). Past it, new asks are refused and nobody is emailed |
| `default_allow_below` | The consequence score under which a call no rule matches is allowed (default `20`; `0` allows nothing by default) |
| `admin_token_env` | Env var holding the token for `/v1/audit` |
| `agents` | `id`, `owner_id` and `api_key_env` for each agent |
| `receivers` | `id` and `api_key_env` for each receiver allowed to call the verify endpoint |
| `upstream_receiver` | The ID of the receiver behind `upstream`. Receipts name it (v1), so no other receiver accepts them. When `receivers` are listed it must be one of them. Unset, receipts are v0 |
| `upstream_auth_env` | Env var holding a token for the upstream, sent as `Authorization: Bearer …` in place of the agent's key. The upstream must be `https`, or `http` to localhost. See [Hosted MCP servers](#hosted-mcp-servers) |
| `owners` | `id` and `approvers` (email addresses) for each owner |
| `local_agent` | For the local modes (the Claude Code hook, `-stdio`): the `id` and `owner_id` calls are recorded under. Default `local` and `local` |
| `stdio_env` | For `-stdio`: names of env vars the wrapped server gets, besides `PATH`, `HOME` and a few other basics. It gets nothing else |
| `stdio_env_file` | For `-stdio`: a file of `NAME=value` lines for the wrapped server, such as its token, readable by its owner alone. Absolute or `~/` |
| `stdio_ask_in_client` | For `-stdio`: ask about held calls through the MCP client, when it can show forms (2026-07-28 clients). Only for clients that show the question to a person. Default `false` |
| `tool_pins` | `disabled: true` stops pinning tool definitions; `unnamed_arguments: allow` lets through arguments a pinned schema doesn't name (default `refuse`). See [Tool definitions](#tool-definitions) |
| `receipts` | `ttl` (default `5m`), `ed25519_key_env`, `mldsa87_key_env`. After a key rotation, `previous_keys_env` names an env var holding the old public keys (what `consequenced -jwks` printed), and `previous_keys_until` says until when receipts signed with them are accepted. Audit heads they signed always verify. See [Rotating the signing keys](docs/receivers.md#rotating-the-signing-keys) |
| `database_url_env` | Env var holding a Postgres URL |
| `state_dir` | A directory for the file store, e.g. `~/.consequence`: absolute, or starting with `~/`. Set this or `database_url_env`, not both. With neither, everything is kept in memory |
| `email` | `smtp_url_env` (e.g. `smtp://user:pass@smtp.example.com:587`, or `smtps://…:465`) and `from`. Without it, approver links go to the server log |
| `allowed_origins` | Browser origins allowed to call `/mcp`. None by default |
| `tools`, `rules` | The policy (see above) |

Generate signing keys with `go run ./cmd/consequenced -genkeys`, or run `make env`, which writes all secrets to `.env`. Validate a config with `make check`.

### Keeping state in files

With `state_dir` set, ConsequenceOS keeps the audit log, approvals, limits and used receipts on disk, with no database:

```yaml
state_dir: ~/.consequence
```

- **A journal.** Every change is one JSON line in `state_dir/journal.jsonl`, synced to disk before the change counts as done. The journal is replayed on start. It holds what Postgres would: argument hashes and summaries, the hashes of approval link tokens, and the arguments shown to approvers.
- **Crashes.** A crash part-way through a write leaves a torn last line. It is dropped with a warning on the next start, since that change was never reported done. A damaged line anywhere else stops the start, naming the line, rather than guessing.
- **Size.** Once the journal has doubled since it was last rewritten, and is at least 1 MiB, it is rewritten from the current state. Every audit entry is kept unchanged. Pruned usage, expired receipts and the steps of each approval are rewritten as one line each.
- **Tampering.** Audit entries are restored exactly as written, so `consequenced -verify-audit` still finds an edited journal. It opens the directory read-only, so it works while the server runs.
- **One process at a time.** The server locks `state_dir` while it runs, and a second one fails after waiting 2 seconds. The operating system frees the lock if the process dies, so a crash never leaves it stuck. The directory is created with mode `0700`, and the journal with `0600`. It works on Linux and macOS.
- **If a write fails,** for example because the disk is full, the store refuses every request until a restart. Calls are not forwarded, and nothing acts on a change the journal lacks.

Every write waits for the disk, so this suits one person or a small team. Use Postgres for heavy traffic, or for several servers.

What it doesn't cover:
- **Entries from before the chain.** Those written before upgrading to a version with the chain have no hashes. Verification counts them as `unhashed` but can't check them.
- **Rewrites after the last saved head.** The chain's hashes need no key, so someone with database access could rebuild everything after your newest saved head. Everything before it is safe while the head is kept somewhere they can't reach. Save heads often. Forging a head itself needs the signing keys.

### Hosted MCP servers

A hosted MCP server, such as GitHub's, needs a token, and it won't check ConsequenceOS receipts. Give the token to ConsequenceOS instead of the agent:

```yaml
upstream: https://api.githubcopilot.com/mcp/
upstream_auth_env: GITHUB_TOKEN      # the env var holding it; the agent never sees it
```

- **How it's sent.** The proxy removes the agent's own key, as always, and sends `Authorization: Bearer <token>` upstream, on every request, event streams included.
- **The guarantee.** Calls are allowed, denied and held exactly as before. Since ConsequenceOS holds the only token, an agent that skipped the proxy would have nothing to call the server with. That is the guarantee here, and receipts don't add to it. So `-check` doesn't ask for `upstream_receiver` when a token is set and no receivers are listed.
- **Keeping it secret.**
  - The token never appears in a log line or the audit log.
  - Every response from the upstream, headers and body, has the token replaced with asterisks, in case the server echoes it back. The proxy asks the upstream for uncompressed or gzip replies it can read, so a compressed body can't hide it.
  - A token holding a space or control character is refused, so it can't add headers.
  - The upstream must be `https`, or `http` to localhost, so the token never crosses a network unencrypted.
- **What it can't stop.** The server could encode the token before echoing it, base64 say, and get past the scrubbing. And the agent must not be able to read the token some other way: from your shell's environment, a file, or a command it runs. For coding agents, see [Guarding Claude Code](docs/claude-code.md).

### Local MCP servers

Many MCP servers run as a local process that the agent starts and talks to over stdin and stdout. Put `consequenced -stdio` in front of one, in the agent's MCP config:

```json
{
  "mcpServers": {
    "github": {
      "command": "consequenced",
      "args": ["-stdio", "-config", "/home/you/.consequence/github.yaml", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

It starts the real server and relays messages both ways. Tool calls, resource reads and prompts go past the policy first, parsed exactly as the HTTP proxy parses them. The config needs only `state_dir`, the rules, and optionally `local_agent`. With no `-config`, it uses `~/.consequence/claude-code.yaml`, the same policy and audit log as the Claude Code hook.

- **Asked calls** are refused with an approval ID and a command for the person: `consequenced -approve apr_…`. The command shows the call and asks on the terminal itself, not stdin. An agent running shell commands has no terminal, so it can't approve its own calls. After approval, the agent's retry of that exact call goes through once. `-reject` says no.
- **Asking in the client.** With `stdio_ask_in_client: true`, a 2026-07-28 client that can show forms is asked instead: "Approve this call?", with the rule, the score and the arguments. The client sends the call again with the answer, and a yes lets it through. This is the spec's multi round-trip pattern, a result with `resultType: "input_required"`. The question's `requestState` is signed with a key that exists only in the wrapper process. It names the approval, the call and its arguments, and it expires after 15 minutes. So a made-up answer, or one sent with other arguments, decides nothing. If the person dismisses the question, the call is refused with the `-approve` command instead of asked again. Other clients, and clients that can't show forms, get the `-approve` command.

  It's off by default because it trusts the client. A client that shows the question to you is as good as the terminal. But some agent frameworks let the model answer such questions, and then the agent would approve its own calls. The audit log records these decisions as made "via the MCP client".
- **The token stays out of the agent's hands.** The server gets `PATH`, `HOME` and a few other basics, the env vars named in `stdio_env`, and the lines of `stdio_env_file`. It gets nothing else from the agent's environment. Put a token in that file (mode `600`, which is enforced), not in the agent's MCP config. The Claude Code hook's starter policy keeps the agent out of `~/.consequence`, so keep the file there.
- **Tool definitions are pinned,** as over HTTP (see [Tool definitions](#tool-definitions)), per server command line. `consequenced -tools` and `consequenced -accept-tool` use the same config as the wrapper.
- **Failing closed.** If the server exits, every call still waiting for it gets an error, and the wrapper exits. If the policy's state can't be opened, the call isn't forwarded. The wrapper opens the state between calls, not for its whole life, so `-approve`, the hook, and wrappers for other servers can share one `state_dir`.
- **Requests from the server** go past the policy, as over HTTP (see [Requests from the server](#requests-from-the-server)). A refused one never reaches the client, and the wrapper answers the server itself. Receipts aren't added: the server is a process you chose to run, not a receiver, and any receipt the agent puts in a call is removed.

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
- `internal/gate`: the decision path for every gated call: assessing it, the policy, approvals, limits and the audit log. It never answers the agent, so each way in is a thin adapter over it.
- `internal/proxy`: the HTTP adapter. It authenticates agents, parses MCP messages, words the gate's answer, and forwards allowed calls with a receipt.
- `internal/policy`, `internal/consequence`, `internal/approval`, `internal/receipt`, `internal/audit`, `internal/store`, `internal/config`: the parts the gate and the proxy are built from.
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
- policy checks on resource reads and prompts, a cap on pending approvals, and approval decisions that are always audited;
- consequence scores, with rules that match on them and the score in the audit log and on the approval page;
- receipt v1, which names its receiver and carries the call's consequence;
- a file store, which keeps state on one machine across restarts with no database;
- a Claude Code hook, which applies the policy to Claude Code's built-in tools;
- pinned tool definitions: a changed tool is hidden from the model and asks until accepted, and arguments its schema doesn't name are refused;
- signing key rotation, with old keys kept for saved audit heads, and offline receivers that pick up new keys by themselves;
- archiving old audit entries to a file that can be checked on its own, without breaking the chain;
- policy checks on what the server asks of the client: elicitation, sampling and roots;
- observe mode, which decides and audits every call but stops none, and a report of what was or would have been stopped;
- policy tests: a table of calls and the decisions they should get, run with `consequenced -test` in CI.

Not yet:
- passkey-signed approvals.

## License

ConsequenceOS is licensed under the [Apache License 2.0](LICENSE).

# Anchoring on Concordium

This is for people who run an agent behind ConsequenceOS and want anyone, not only themselves, to be able to check its record. `consequence-anchor` gives the agent an identity in [Concordium's Agent Registry](https://docs.concordium.com/en/mainnet/technical-reference/agent-registry/index.html). It then writes the head of ConsequenceOS's audit log into the agent's record there, on a public chain the server's operator can't rewrite.

## What it proves

ConsequenceOS records every decision in a [hash-chained audit log](../README.md#audit-log). A chain shows an entry was edited, but not that its newest entries were removed, or that someone with database access rebuilt the whole log. A **signed head** saved elsewhere closes that gap: "entry 4182 had hash `sha256:…`". Later, the log must still contain that entry with that hash.

Saving heads only helps if the operator can't quietly change where they're saved. Anchoring puts them in the agent's registry record, where:

- **only the agent's owner can write** (the registry contract enforces it), and the chain records when;
- **anyone can read**, from any Concordium node, with no account and no token;
- **nothing can be rewritten.** An anchored head stays checkable forever: later anchors replace the record's current value, but every earlier one stays in its transaction.

What a counterparty can check, with nothing but the chain:

1. the agent is registered and **active**, with its **badge**, the token address other agents look it up by;
2. its **Agent Card** is the one the registry pinned (same SHA-256), and the card says the agent is **guarded by ConsequenceOS**, at which server, with which public keys;
3. the anchored head is **signed by those keys** (with `-head`), and names an entry the log must still contain.

The operator, or an auditor with the server's config, then runs `consequenced -verify-audit -audit-head FILE` to check the log still contains it.

## What goes on-chain

The registry stores at most 485 bytes per value. A signed head is about 6.6 KB, because of its post-quantum ML-DSA-87 signature. So the anchor is small JSON, under the registry key `consequenceos.audit_head`:

```json
{"hash":"sha256:9c1f…","head":"sha256:41ab…","seq":4182}
```

- `seq` and `hash` are the entry's place and chain hash: what the log must still contain.
- `head` is the SHA-256 of the whole signed head, which `anchor` saves to `anchored-heads/head-4182.json` before sending. Publish those files, or keep them where auditors can reach them; each one matches exactly one anchor.

## Setting up

You need:

- **A Concordium account.** Make one on testnet in Concordium's browser wallet, and get free test CCD from the [faucet](https://docs.concordium.com/en/mainnet/tutorials/plt/request-ccd.html). Export the account's private key, which gives a JSON key file, and keep it readable by you alone (`chmod 600`). Anchoring a head uses a few thousand energy, a small fee in CCD.
- **A ConsequenceOS server** with a `public_url` and its admin token in `$CONSEQUENCE_ADMIN_TOKEN`.
- **Somewhere to host one small JSON file**, the Agent Card, at a stable HTTPS URL: GitHub Pages, a bucket, your own site.

`consequence-anchor` comes in the release archives beside `consequenced`. To build it from source: `cd cmd/consequence-anchor && go build .`. Every command takes `-network testnet` (the default) or `mainnet`.

```bash
# 1. Register the agent. It prints the agent's token ID and badge.
consequence-anchor register -account my-account.export
#   Registered agent 1168 on testnet, owned by 3dt3UMPz...
#     badge:       JyP9Wc2XhkYP7aw6JNnif
#     transaction: https://testnet.ccdscan.io/?dcount=1&dentity=transaction&dhash=...

# 2. Write its card, naming the guard. Host the file unchanged at -url.
consequence-anchor card -account my-account.export -token 1168 \
  -url https://agents.example.com/refund-bot.json \
  -name "Refund bot" -description "Issues refunds under a ConsequenceOS policy" \
  -server https://consequence.example.com

# 3. Pin the hosted card to the agent: its URL and SHA-256.
consequence-anchor set-card -account my-account.export -token 1168 \
  -url https://agents.example.com/refund-bot.json -file agent-card.json

# 4. Anchor the audit log's head. Run it from cron, or keep it running.
consequence-anchor anchor -account my-account.export -token 1168 \
  -server https://consequence.example.com -every 1h
```

To register and pin in one transaction, write the card first without `-token`, host it, and run `register -card-url URL`. The card then has no token address. That's allowed, but rerunning steps 2 and 3 adds it.

## What `anchor` checks first

Anchoring a new head over a log that was cut back or rebuilt would vouch for the rewrite. So before anything is sent:

1. The agent must be **active and owned** by the account whose keys were given. Its card must match its pinned hash, and the card's guard must be **this server**: a head signed under another issuer is refused.
2. The server must check its whole log **and still contain the head anchored last**. This is `GET /v1/audit/verify?seq=…&hash=…`.
3. The new head must **verify with the server's published keys** and come **at or after** the anchored entry: not behind it, and not the same entry with a different hash.

If the log doesn't hold up, nothing is sent and `anchor` exits with status 1. The anchor already on-chain stays as evidence of the log before the change. With `-every`, a network error is retried at the next interval, but this kind of refusal stops it, so whatever runs it can alert. When the head hasn't moved, nothing is sent and nothing is paid.

Every transaction is tried as a free dry run first, so one the registry would refuse costs nothing. The tool also checks the node it talks to is on the network asked for, by its genesis block, so test CCD and real CCD can't be mixed up.

## Checking an agent

Anyone can check an agent, with no keys and no token:

```bash
consequence-anchor verify -token 1168 -head head-4182.json
#   agent 1168 on testnet, badge JyP9Wc2XhkYP7aw6JNnif
#     owner:  3dt3UMPz...
#     status: active
#     card:   https://agents.example.com/refund-bot.json, matches the SHA-256 the registry pinned
#     guard:  ConsequenceOS at https://consequence.example.com, keys at https://consequence.example.com/.well-known/consequence-keys
#     anchor: entry 4182, sha256:9c1f...
#             signed head sha256:41ab...
#     head:   head-4182.json is the anchored head, signed by https://consequence.example.com at 2026-12-01T10:00:00Z
#   ok
```

It exits with status 1 and prints a `PROBLEM:` line for anything that doesn't hold up: a revoked agent, a card that changed since it was pinned, a head file that isn't the anchored one, or one signed by keys other than those the card names.

`verify` reads the chain through a Concordium node, so it trusts Concordium and not the agent's operator. The registry's hosted service can show the same badge (`https://agent-registry-mcp.concordium.com/v1/check-badge/BADGE`), but `verify` doesn't depend on it.

## Agent card extension v0

The card is an [A2A Agent Card](https://a2a-protocol.org) with two extensions in `capabilities.extensions`. The first is the Concordium badge block every registered agent's card carries. The second is ConsequenceOS's:

```json
{
  "uri": "https://github.com/matutozi/consequence-os/blob/main/docs/concordium.md#agent-card-extension-v0",
  "description": "Guarded by ConsequenceOS: …",
  "required": false,
  "params": {
    "issuer": "https://consequence.example.com",
    "keys": "https://consequence.example.com/.well-known/consequence-keys",
    "anchorKey": "consequenceos.audit_head"
  }
}
```

- `issuer` is the server's `public_url`, as its signed heads and receipts name it.
- `keys` is its JWKS. Receivers use the same keys to check receipts, so a counterparty that finds the card also knows how to check a receipt from this agent.
- `anchorKey` is the registry metadata key the head is anchored under.

A card with this extension twice, or with other params in it, is refused. A later version gets a new `uri`.

## The demo

`scripts/demo-concordium.sh` (or `make demo-concordium`) runs the whole story on testnet, against a local server and the mock tool server:

1. The agent's calls are allowed, denied and held, and logged.
2. The head is anchored, and `verify` checks the agent from the chain.
3. An insider deletes the held $5,000 refund from the log on disk. The server's own chain check still says **intact**, because what's left is a valid chain.
4. `anchor` refuses, since the log no longer contains the head on-chain, and `-verify-audit -audit-head` names the missing entry.
5. The log is put back, so the demo can run again.

```bash
export CONCORDIUM_ACCOUNT=~/my-account.export
CARD_URL=https://raw.githubusercontent.com/you/repo/main/refund-bot.json scripts/demo-concordium.sh setup   # once
scripts/demo-concordium.sh                                                                                  # each time
```

`setup` registers the agent, writes its card and waits while you host it, then pins it. Each run sends one transaction. The server's keys, log and anchored heads stay in `~/.consequence/concordium-demo` (`DEMO_DIR`), because the chain holds anchors of that log.

## Limits

- **An agent with an external reference can't be read.** An external reference is a key on another chain, bound with CIS-8. The registry's binary format for it isn't documented, and the fields after it can only be found by reading it. `consequence-anchor` registers agents without one.
- **The registry's error codes aren't documented.** A refused transaction shows the contract's code, for example `-7208` for a value with a zero byte. Anchors are JSON, so they never hold one.
- **The heads between anchors are only as safe as the log.** Anchoring once an hour means up to an hour of entries rest on the log alone. Anchor more often for less.
- **Concordium's Go SDK** is the newest release, v0.4.0 from February 2025. The tool was checked against testnet on protocol 9 in November 2026. It's a separate Go module, so the SDK and gRPC never become dependencies of `consequenced`.

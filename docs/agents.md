# Connecting an agent

This is for people building or running AI agents. The agent's code barely changes: it talks MCP to ConsequenceOS instead of to the tool server, and sends an API key.

## 1. Get an API key

Whoever runs ConsequenceOS lists your agent in `consequence.yaml`:

```yaml
agents:
  - id: support-bot
    owner_id: acme                         # the owner whose approvers decide held calls
    api_key_env: CONSEQUENCE_KEY_SUPPORT_BOT
```

The key itself is in that env var on the server, and you get the same value for the agent.

## 2. Point the agent at ConsequenceOS

Use ConsequenceOS's `/mcp` URL wherever you had the tool server's, and send the key as a Bearer token. With the official MCP Python SDK:

```python
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {api_key}"})
async with http, Client(streamable_http_client("https://consequence-os.example/mcp", http_client=http)) as client:
    result = await client.call_tool("payments.refund", {"charge_id": "ch_123", "amount": 20})
```

A runnable version is in [examples/python-agent](../examples/python-agent/agent.py). Any MCP client that speaks Streamable HTTP works: revision 2026-07-28, or older clients that use `initialize`.

`tools/call`, `resources/read` and `prompts/get` are checked. Everything else, such as `tools/list` and notifications, passes through unchanged.

## 3. Handle the three outcomes

A tool call comes back in one of three ways:

| What happened | What the agent receives | What the agent should do |
|---|---|---|
| **Allowed** | The tool's normal result | Carry on. |
| **Blocked** by policy | A tool error (`isError: true`) starting `Blocked by ConsequenceOS: policy rule "…"` | Don't retry. Tell the user it isn't allowed. |
| **Held** for a human | A tool error starting `Approval pending`, with an approval ID and a status link | Tell the user it's waiting for approval and share the link. Once it's approved, retry the **exact same call** with the same arguments. It goes through once. |
| **Refused** because too many are waiting | A tool error starting `Refused by ConsequenceOS: this agent already has … requests waiting` | Don't retry this or similar calls. Tell the user requests are waiting for their decision. |

Reads come back the same way, except that a blocked or held `resources/read` or `prompts/get` is a JSON-RPC error with code `-32030`, not a tool result. Its message starts with the same words.

Some details about held calls:

- **An approval covers one call.** It's for exactly that tool and those argument values. Key order and spacing don't matter, but changing any value needs a new approval.
- **There's a retry window.** After the approval, the retry must come within the approval validity (10 minutes by default). If nobody decides within the approval timeout (1 hour by default), the request expires, and asking again opens a new one.
- **A rejection sticks.** For the validity window, the same call returns `Rejected: an approver declined …`. Don't keep retrying.
- **The agent can't approve its own call.** It only gets the read-only status link, never an approver's link.

The messages are written so a language model can act on them as they are. If your agent has a planner, you can also match on the prefixes above.

## 4. What the agent can't do

- **Bypass the policy.** Requests are refused before the policy runs if their JSON could be read two ways: duplicate keys, keys that differ only in case (`amount` and `Amount`), or batches.
- **Supply its own receipt.** ConsequenceOS removes any receipt the agent sends and attaches its own.
- **Call the tool server directly** if the tool server checks receipts (see [Protecting a tool server](receivers.md)). Without a receipt, the call is refused.

## Errors that aren't policy decisions

| HTTP status | Meaning |
|---|---|
| `401` | Missing or wrong API key. |
| `403` | The request came from a browser page whose origin isn't in `allowed_origins`. |
| `400` | The request was malformed or ambiguous, or its MCP headers don't match its body. A resource URI with `.` or `..` segments or percent-encoded letters is refused too. Fix the request. |
| `502` | The tool server is down. |
| `503` | The audit log, approvals, usage limits or receipt signing are unavailable. ConsequenceOS fails closed, so nothing was forwarded and you can retry later. |

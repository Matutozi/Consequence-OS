# Protecting a tool server

This is for people who run the service an agent's tool calls end up at: an MCP server in front of your API, database, repository or cloud account. ConsequenceOS's policy only protects you if your service refuses calls that didn't go through it. That's what the receipt check does.

## How it works

For every call it allows, ConsequenceOS signs a **receipt** and attaches it to the request it forwards, both in the `X-Consequence-Receipt` header and in `params._meta.consequenceReceipt`. Before your service acts, it checks that the receipt:

- is signed by ConsequenceOS, with both of its keys;
- hasn't expired (receipts last 5 minutes by default);
- is for **this tool** and **exactly these arguments**, compared by a hash of their canonical JSON;
- hasn't been used before.

A call that fails any of these is refused with HTTP 403, before your code runs. The receipt also tells your code who allowed the call (a policy rule or a named approver), which you can log or show.

## 1. Register the service

Whoever runs ConsequenceOS lists your service under `receivers`, with an env var holding its key:

```yaml
receivers:
  - id: payments-api
    api_key_env: CONSEQUENCE_KEY_RECEIVER_PAYMENTS
```

Give your service the same key. Each check uses a receipt up, which is why only listed receivers may make checks.

## 2. Add the check

**Go** (`net/http`):

```go
import "github.com/matutozi/consequence-os/pkg/verify"

guard := verify.Middleware(verify.NewClient("https://consequence-os.example", os.Getenv("CONSEQUENCE_KEY_RECEIVER_PAYMENTS")), nil)
mux.Handle("/mcp", guard(yourMCPServer))
// in a handler: rcpt, _ := verify.FromContext(r.Context())
```

**Python** (FastAPI or Starlette):

```python
from consequence_verify import Client, ReceiptMiddleware, receipt_from

app.add_middleware(
    ReceiptMiddleware,
    verifier=Client("https://consequence-os.example", os.environ["CONSEQUENCE_KEY_RECEIVER_PAYMENTS"]),
    paths=["/mcp"],
)
# in a route: receipt_from(request)
```

Install it with `pip install "git+https://github.com/Matutozi/Consequence-OS.git#subdirectory=python"`. See [python/README.md](../python/README.md) for details.

**Anything else:** before acting on a `tools/call`, make one HTTP call:

```bash
curl -s https://consequence-os.example/v1/receipts/verify \
  -H "Authorization: Bearer $CONSEQUENCE_KEY_RECEIVER_PAYMENTS" -H 'Content-Type: application/json' \
  -d '{"receipt": <the X-Consequence-Receipt value>, "tool": "<params.name>", "arguments": <params.arguments>}'
# {"valid": true, "receipt": {...}}   or   {"valid": false, "reason": "params_mismatch", ...}
```

Act only on `"valid": true`. Treat any other answer, or no answer, as a refusal. Pass the arguments exactly as you received them: the server canonicalizes them itself.

## 3. Read the arguments safely

The check compares the arguments ConsequenceOS approved with the ones in the request. That only protects you if your code reads the same values. The Go and Python middleware refuse requests whose JSON could be read two ways, such as duplicate keys or keys that differ only in case. If you write your own check, refuse those too: many JSON parsers silently keep the last duplicate.

## 4. Check claims against your own records

A receipt proves that ConsequenceOS approved these exact arguments. It can't prove the arguments are true. If the policy relies on an argument that describes something your service owns, look it up before acting. For example, if a rule allows purchase orders under $500 and the agent sends `{"order": "P00231", "amount": 300}`, check that P00231 really is $300. Otherwise an agent could understate the amount to get past the policy.

## Offline checks

The Go package can also check a receipt without contacting ConsequenceOS. Fetch the public keys once from `/.well-known/consequence-keys`, then use `&verify.Offline{Keys: keys}`. It checks signatures, expiry, the tool and the arguments, but it **can't enforce single use**, so keep your own record of used receipt IDs if you rely on it.

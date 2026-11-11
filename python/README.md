# consequence-verify

ASGI middleware for FastAPI and Starlette. It refuses an MCP tool call unless it carries a valid [ConsequenceOS](https://github.com/Matutozi/Consequence-OS) receipt for exactly that tool and those arguments. It's the Python version of the Go package `pkg/verify`, and behaves the same way.

## Install

```bash
pip install "git+https://github.com/Matutozi/Consequence-OS.git#subdirectory=python"
```

It needs Python 3.11 or newer, and depends on `starlette` and `httpx`.

## Use

```python
import os

from fastapi import FastAPI, Request
from consequence_verify import Client, ReceiptMiddleware, receipt_from

app = FastAPI()
app.add_middleware(
    ReceiptMiddleware,
    verifier=Client("http://consequence-os:8080", os.environ["CONSEQUENCE_KEY_RECEIVER_PAYMENTS"]),
    paths=["/mcp"],
)

@app.post("/mcp")
async def mcp(request: Request):
    receipt = receipt_from(request)  # the verified receipt: who allowed this, and under which rule
    ...
```

The API key is this receiver's key. List the receiver under `receivers` in the ConsequenceOS config, with the env var that holds the same key.

## What it does

For each `POST` under `paths` that is an MCP `tools/call`:

1. It reads the receipt from the `X-Consequence-Receipt` header, or from `params._meta.consequenceReceipt` if the header is absent.
2. It calls `POST /v1/receipts/verify` once. That call checks both signatures, the expiry, the tool, the exact arguments, and that the receipt hasn't been used before. It also uses the receipt up, so the check runs right before the action.
3. It lets the request through only if the receipt is valid. Otherwise it answers HTTP 403 with JSON-RPC error `-31001` and a reason code (`missing`, `params_mismatch`, `already_used`, `expired`, `wrong_audience`, and so on). `wrong_audience` means a v1 receipt made out to another receiver: the server knows which receiver is asking from its API key.

It also refuses, with reason `malformed`, any body that two JSON parsers could read differently:

- duplicate keys, like `{"amount": 10, "amount": 5000}`;
- keys that differ only in letter case, like `amount` and `Amount`;
- `NaN` and `Infinity`;
- a body over 4 MiB.

Python's `json` module would otherwise keep the last duplicate, so a tool could act on an amount the policy never saw.

Other requests, such as `tools/list`, notifications, `GET`, and paths outside `paths`, pass through untouched.

If the ConsequenceOS server can't be reached, the call is refused.

## Not included

There's no offline verification. Checking the post-quantum ML-DSA-87 signature locally would need a library beyond `httpx` and `starlette`, and offline checks can't enforce single use anyway. The Go package has an offline mode if you need one.

## Develop

```bash
cd python
python -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest
```

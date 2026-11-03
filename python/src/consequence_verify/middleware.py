"""ASGI middleware that refuses MCP tool calls without a valid receipt."""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from typing import Any

from ._json import AmbiguousJSON, loads_strict
from .client import ReceiptRejected, Verifier

HEADER_NAME = "x-consequence-receipt"  # ASGI header names are lower-case bytes
META_KEY = "consequenceReceipt"
CODE_RECEIPT_REJECTED = -31001  # outside JSON-RPC's reserved range
MAX_BODY_BYTES = 4 << 20
STATE_KEY = "consequence_receipt"

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

log = logging.getLogger("consequence_verify")


class ReceiptMiddleware:
    """Every MCP tools/call must carry a valid receipt for exactly that tool
    and those arguments, or it's refused with HTTP 403 before the app runs.
    Other requests pass through untouched.

    With FastAPI::

        app.add_middleware(ReceiptMiddleware, verifier=Client(url, key), paths=["/mcp"])

    The verified receipt is then at ``request.state.consequence_receipt``.

    paths limits the check to requests whose path starts with one of them.
    Use it: without it, every POST body in the app is read and checked.
    """

    def __init__(self, app: ASGIApp, verifier: Verifier, paths: Iterable[str] | None = None) -> None:
        self.app = app
        self.verifier = verifier
        self.paths = tuple(paths) if paths is not None else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST" or not self._covers(scope["path"]):
            await self.app(scope, receive, send)
            return

        body = await _read_body(receive)
        if body is None:
            await _reject(send, None, "malformed", "receipt is malformed")
            return
        replay = _replaying(body, receive)  # the app reads the same body again

        try:
            message = loads_strict(body)
        except AmbiguousJSON:
            await _reject(send, None, "malformed", "receipt is malformed")  # never let it reach a tool
            return
        except ValueError:
            await self.app(scope, replay, send)  # not JSON: the server answers with a parse error
            return

        call = _parse_call(message)
        if call is None:
            await self.app(scope, replay, send)
            return
        request_id, tool, arguments, meta_receipt = call
        if not tool:
            await _reject(send, request_id, "malformed", "receipt is malformed")
            return

        receipt = _header(scope, HEADER_NAME) or meta_receipt
        if not receipt:
            log.warning("tools/call refused: no receipt", extra={"tool": tool})
            await _reject(send, request_id, "missing", "no receipt was provided")
            return
        try:
            verified = await self.verifier.verify(receipt, tool, arguments)
        except ReceiptRejected as e:
            log.warning("tools/call refused", extra={"tool": tool, "reason": e.reason})
            await _reject(send, request_id, e.reason, e.message)
            return

        log.info("receipt verified", extra={"tool": tool, "receipt_id": verified.get("receipt_id")})
        scope.setdefault("state", {})[STATE_KEY] = verified
        await self.app(scope, replay, send)

    def _covers(self, path: str) -> bool:
        return self.paths is None or any(path.startswith(p) for p in self.paths)


def _parse_call(message: Any) -> tuple[Any, str, Any, str | dict[str, Any] | None] | None:
    """Pick out (id, tool, arguments, receipt from _meta) from a tools/call, or None."""
    if not isinstance(message, dict) or message.get("method") != "tools/call":
        return None
    params = message.get("params")
    params = params if isinstance(params, dict) else {}
    meta = params.get("_meta")
    meta_receipt = meta.get(META_KEY) if isinstance(meta, dict) else None
    tool = params.get("name")
    return message.get("id"), tool if isinstance(tool, str) else "", params.get("arguments"), meta_receipt


async def _read_body(receive: Receive) -> bytes | None:
    """Read the whole request body, or None when it's over MAX_BODY_BYTES."""
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            return None  # the client went away
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


def _replaying(body: bytes, receive: Receive) -> Receive:
    """A receive that gives the app the body we already read, then defers to the real one."""
    sent = False

    async def replay() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay


def _header(scope: Scope, name: str) -> str | None:
    for key, value in scope.get("headers", []):
        if key.decode("latin-1").lower() == name:
            return value.decode("latin-1")
    return None


async def _reject(send: Send, request_id: Any, reason: str, message: str) -> None:
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": CODE_RECEIPT_REJECTED,
            "message": "ConsequenceOS receipt rejected: " + message,
            "data": {"reason": reason},
        },
    }).encode()
    await send({
        "type": "http.response.start",
        "status": 403,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
    })
    await send({"type": "http.response.body", "body": body})


def receipt_from(request: Any) -> dict[str, Any] | None:
    """The receipt the middleware verified for this request, if any."""
    return getattr(request.state, STATE_KEY, None)

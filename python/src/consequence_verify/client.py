"""Verify receipts with one call to the ConsequenceOS server."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Protocol

import httpx

from ._json import dumps_exact

VERIFY_PATH = "/v1/receipts/verify"


class ReceiptRejected(Exception):
    """The receipt doesn't allow this call. The call must not run.

    reason is a stable code, the same as the Go package and the server use:
    malformed, unknown_key, bad_signature, not_canonical, expired,
    not_yet_valid, tool_mismatch, params_mismatch, already_used, missing,
    wrong_audience (a v1 receipt for another receiver), or invalid for
    anything else (such as the server being unreachable).
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


class Verifier(Protocol):
    """Anything that can check a receipt; Client is the real one."""

    async def verify(self, receipt: str | dict[str, Any], tool: str, arguments: Any) -> dict[str, Any]:
        """Return the verified receipt, or raise ReceiptRejected."""
        ...


class Client:
    """Checks receipts with POST /v1/receipts/verify.

    This is the full check: both signatures, expiry, the audience, the
    tool, the exact arguments, and single use. A check uses the receipt up,
    so call it only right before the action runs. The server knows which
    receiver is asking from api_key, and refuses a v1 receipt made out to
    another one.

    api_key is this receiver's key, listed under ``receivers`` in the
    server's config.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 10.0,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required: list this receiver under receivers in the server config")
        self._url = base_url.rstrip("/") + VERIFY_PATH
        self._headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        self._timeout = timeout
        self._http = http
        self._owns_http = http is None
        self._loop: asyncio.AbstractEventLoop | None = None

    def _client(self) -> httpx.AsyncClient:
        """The HTTP client to use on the running event loop.

        Pooled connections belong to the loop that opened them. A server
        runs one loop, but Starlette's TestClient starts a new one per
        request, so a client we made ourselves is remade when the loop changes.
        """
        if self._owns_http:
            loop = asyncio.get_running_loop()
            if self._http is None or self._loop is not loop:
                self._http = httpx.AsyncClient(timeout=self._timeout)
                self._loop = loop
        assert self._http is not None
        return self._http

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()

    async def verify(self, receipt: str | dict[str, Any], tool: str, arguments: Any) -> dict[str, Any]:
        if isinstance(receipt, str):
            try:
                receipt = json.loads(receipt)  # the header carries the receipt object as JSON text
            except ValueError:
                raise ReceiptRejected("malformed", "receipt is malformed") from None
        body = dumps_exact({"receipt": receipt, "tool": tool, "arguments": {} if arguments is None else arguments})

        try:
            resp = await self._client().post(self._url, content=body, headers=self._headers)
        except httpx.HTTPError as e:
            # Can't reach the server: refuse rather than run unchecked.
            raise ReceiptRejected("invalid", f"verify: {e}") from e
        if resp.status_code == 401:
            raise ReceiptRejected("invalid", "verify: the server did not accept this receiver's API key")
        try:
            out = resp.json()
        except ValueError:
            raise ReceiptRejected("invalid", f"verify: HTTP {resp.status_code} with unreadable body") from None

        if not isinstance(out, dict) or out.get("valid") is not True or not isinstance(out.get("receipt"), dict):
            reason = out.get("reason", "invalid") if isinstance(out, dict) else "invalid"
            message = out.get("message", "receipt rejected") if isinstance(out, dict) else "receipt rejected"
            raise ReceiptRejected(reason, message)
        return out["receipt"]

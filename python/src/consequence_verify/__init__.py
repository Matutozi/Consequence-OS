"""Refuse MCP tool calls that don't carry a valid ConsequenceOS receipt.

The Python counterpart of the Go package github.com/matutozi/consequence-os/pkg/verify:

    from fastapi import FastAPI
    from consequence_verify import Client, ReceiptMiddleware

    app = FastAPI()
    app.add_middleware(
        ReceiptMiddleware,
        verifier=Client("http://consequence-os:8080", os.environ["CONSEQUENCE_KEY_RECEIVER_PAYMENTS"]),
        paths=["/mcp"],
    )
"""

from ._json import AmbiguousJSON, loads_strict
from .client import Client, ReceiptRejected, Verifier
from .middleware import CODE_RECEIPT_REJECTED, ReceiptMiddleware, receipt_from

__all__ = [
    "AmbiguousJSON",
    "CODE_RECEIPT_REJECTED",
    "Client",
    "ReceiptMiddleware",
    "ReceiptRejected",
    "Verifier",
    "loads_strict",
    "receipt_from",
]

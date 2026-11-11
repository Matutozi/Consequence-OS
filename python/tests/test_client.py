import asyncio
import json

import httpx
import pytest

from consequence_verify import Client, ReceiptRejected

RECEIPT = {"payload": "e30", "signatures": []}


def client_answering(status, body, seen=None):
    """A Client whose server answers every request with status and body."""

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        content = body if isinstance(body, bytes) else json.dumps(body).encode()
        return httpx.Response(status, content=content)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return Client("http://cos.test/", "recv-key", http=http)


def verify(client, receipt=RECEIPT, tool="payments.refund", arguments=None):
    return asyncio.run(client.verify(receipt, tool, arguments))


def test_valid_receipt_is_returned_and_request_is_right():
    seen = []
    c = client_answering(200, {"valid": True, "receipt": {"receipt_id": "rcpt_1"}}, seen)
    got = verify(c, receipt=json.dumps(RECEIPT), arguments={"amount": 20})

    assert got == {"receipt_id": "rcpt_1"}
    req = seen[0]
    assert str(req.url) == "http://cos.test/v1/receipts/verify"
    assert req.headers["authorization"] == "Bearer recv-key"
    assert json.loads(req.content) == {"receipt": RECEIPT, "tool": "payments.refund", "arguments": {"amount": 20}}


@pytest.mark.parametrize(
    ("status", "body", "reason"),
    [
        (200, {"valid": False, "reason": "params_mismatch", "message": "receipt does not match these arguments"}, "params_mismatch"),
        (200, {"valid": False, "reason": "already_used", "message": "receipt has already been used"}, "already_used"),
        (200, {"valid": False, "reason": "wrong_audience", "message": "receipt is for a different receiver"}, "wrong_audience"),
        (401, {"valid": False, "reason": "unauthorized"}, "invalid"),
        (503, {"valid": False, "reason": "unavailable", "message": "could not verify right now"}, "unavailable"),
        (502, b"<html>bad gateway</html>", "invalid"),
        (200, {"valid": True}, "invalid"),  # "valid" without a receipt is not good enough
    ],
)
def test_anything_but_a_valid_answer_is_a_rejection(status, body, reason):
    with pytest.raises(ReceiptRejected) as e:
        verify(client_answering(status, body))
    assert e.value.reason == reason


def test_v1_receipt_fields_come_through():
    v1 = {
        "type": "consequenceos.receipt.v1",
        "receipt_id": "rcpt_1",
        "audience": "payments-api",
        "consequence": {"score": 80, "reversibility": "none", "source": "config"},
    }
    assert verify(client_answering(200, {"valid": True, "receipt": v1})) == v1


def test_unreachable_server_is_a_rejection():
    def handler(request):
        raise httpx.ConnectError("connection refused")

    c = Client("http://cos.test", "k", http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(ReceiptRejected) as e:
        verify(c)
    assert e.value.reason == "invalid"


def test_receipt_header_that_is_not_json():
    with pytest.raises(ReceiptRejected) as e:
        verify(client_answering(200, {}), receipt="not json")
    assert e.value.reason == "malformed"


def test_api_key_is_required():
    with pytest.raises(ValueError):
        Client("http://cos.test", "")

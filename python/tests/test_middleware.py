import json

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from consequence_verify import CODE_RECEIPT_REJECTED, ReceiptMiddleware, ReceiptRejected, receipt_from

GOOD = '{"payload":"good","signatures":[]}'


class FakeVerifier:
    """Accepts the receipt GOOD for any call, and records what it was asked."""

    def __init__(self):
        self.calls = []

    async def verify(self, receipt, tool, arguments):
        self.calls.append((receipt, tool, arguments))
        if receipt in (GOOD, json.loads(GOOD)):
            return {"receipt_id": "rcpt_1", "action": {"tool": tool}}
        raise ReceiptRejected("bad_signature", "receipt signature does not verify")


def make_app(verifier, paths=("/mcp",)):
    app = FastAPI()
    app.add_middleware(ReceiptMiddleware, verifier=verifier, paths=paths)
    app.state.seen = []

    @app.post("/mcp")
    async def mcp(request: Request):
        body = await request.json()  # the app can still read the body
        app.state.seen.append(body)
        rcpt = receipt_from(request)
        return {"jsonrpc": "2.0", "id": body.get("id"), "result": {"receipt_id": rcpt and rcpt["receipt_id"]}}

    @app.post("/upload")
    async def upload(request: Request):
        return {"size": len(await request.body())}

    return app


def tools_call(arguments, meta=None, name="payments.refund"):
    params = {"name": name, "arguments": arguments}
    if meta is not None:
        params["_meta"] = meta
    return {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params}


@pytest.fixture
def setup():
    v = FakeVerifier()
    app = make_app(v)
    return v, app, TestClient(app)


def rejected(resp, reason):
    assert resp.status_code == 403
    err = resp.json()["error"]
    assert err["code"] == CODE_RECEIPT_REJECTED
    assert err["data"]["reason"] == reason
    return resp.json()


def test_valid_receipt_in_header_reaches_the_app(setup):
    v, app, client = setup
    resp = client.post("/mcp", json=tools_call({"amount": 20}), headers={"X-Consequence-Receipt": GOOD})
    assert resp.status_code == 200
    assert resp.json()["result"]["receipt_id"] == "rcpt_1"
    assert v.calls == [(GOOD, "payments.refund", {"amount": 20})]
    assert app.state.seen[0]["params"]["arguments"] == {"amount": 20}


def test_receipt_in_meta_works_too(setup):
    v, _, client = setup
    resp = client.post("/mcp", json=tools_call({"amount": 20}, meta={"consequenceReceipt": json.loads(GOOD)}))
    assert resp.status_code == 200


def test_header_wins_over_meta(setup):
    v, _, client = setup
    client.post(
        "/mcp",
        json=tools_call({"amount": 20}, meta={"consequenceReceipt": {"payload": "other"}}),
        headers={"X-Consequence-Receipt": GOOD},
    )
    assert v.calls[0][0] == GOOD


def test_missing_receipt(setup):
    v, app, client = setup
    body = rejected(client.post("/mcp", json=tools_call({"amount": 20})), "missing")
    assert body["id"] == 7
    assert body["error"]["message"] == "ConsequenceOS receipt rejected: no receipt was provided"
    assert app.state.seen == [] and v.calls == []


def test_rejected_receipt_never_reaches_the_app(setup):
    _, app, client = setup
    resp = client.post("/mcp", json=tools_call({"amount": 20}), headers={"X-Consequence-Receipt": '{"payload":"forged"}'})
    rejected(resp, "bad_signature")
    assert app.state.seen == []


@pytest.mark.parametrize(
    "raw",
    [
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payments.refund","arguments":{"amount":10,"amount":5000}}}',
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payments.refund","arguments":{"amount":10,"Amount":5000}}}',
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payments.refund","arguments":{"amount":NaN}}}',
    ],
)
def test_ambiguous_bodies_are_refused_even_with_a_good_receipt(setup, raw):
    v, app, client = setup
    resp = client.post("/mcp", content=raw, headers={"X-Consequence-Receipt": GOOD, "Content-Type": "application/json"})
    rejected(resp, "malformed")
    assert app.state.seen == [] and v.calls == []


def test_tools_call_without_a_name(setup):
    _, _, client = setup
    rejected(client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}, headers={"X-Consequence-Receipt": GOOD}), "malformed")


@pytest.mark.parametrize(
    "body",
    [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ],
)
def test_other_mcp_messages_pass_through(setup, body):
    v, app, client = setup
    assert client.post("/mcp", json=body).status_code == 200
    assert v.calls == []


def test_paths_outside_the_list_are_not_touched(setup):
    v, _, client = setup
    assert client.post("/upload", content=b'{"method":"tools/call"}').json() == {"size": 23}
    assert v.calls == []


def test_get_requests_pass_through(setup):
    _, _, client = setup
    assert client.get("/mcp").status_code == 405  # FastAPI's own answer: only POST is routed


def test_oversized_body_is_refused(setup):
    _, app, client = setup
    big = json.dumps(tools_call({"blob": "x" * (5 << 20)}))
    rejected(client.post("/mcp", content=big, headers={"X-Consequence-Receipt": GOOD}), "malformed")
    assert app.state.seen == []


def test_real_client_works_across_event_loops():
    """TestClient runs every request on a new event loop; the Client's own
    connection pool must not be reused across them."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from consequence_verify import Client

    class VerifyServer(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            body = b'{"valid":true,"receipt":{"receipt_id":"rcpt_1"}}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), VerifyServer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = TestClient(make_app(Client(f"http://127.0.0.1:{server.server_port}", "k")))
        for _ in range(3):
            resp = client.post("/mcp", json=tools_call({"amount": 20}), headers={"X-Consequence-Receipt": GOOD})
            assert resp.status_code == 200
    finally:
        server.shutdown()

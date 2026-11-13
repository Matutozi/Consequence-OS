package proxy

import (
	"strings"
	"testing"
	"time"
)

func listingLine(tools ...string) string {
	return `{"jsonrpc":"2.0","id":$ID,"result":{"tools":[` + strings.Join(tools, ",") + `]}}`
}

func TestStdioPinsTools(t *testing.T) {
	f := newStdioFixtureWith(t, true)
	f.serverLists(listingLine(notesTool, refundDef))
	f.send(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if got := strings.Join(toolNames(t, f.recv()), ","); got != "notes.read,payments.refund" {
		t.Fatalf("first listing: %s", got)
	}

	// The server changes notes.read and answers with another spelling of
	// the ID, which a client may read as the same.
	f.serverLists(strings.Replace(listingLine(notesTool2, refundDef), "$ID", "$ID.0", 1))
	f.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	got := f.recv()
	if names := strings.Join(toolNames(t, got), ","); names != "payments.refund" || strings.Contains(got, "id_rsa") {
		t.Errorf("listing after the change: %s", got)
	}

	f.send(stdioCall(3, "notes.read", `{"note_id":"welcome"}`))
	if got := f.recv(); !strings.Contains(got, "Approval pending") || !strings.Contains(got, "consequenced -accept-tool notes.read") {
		t.Errorf("call to the changed tool: %s", got)
	}
	f.send(stdioCall(4, "payments.refund", `{"charge_id":"ch_1","amount":5,"refund_all":true}`))
	if got := f.recv(); !strings.Contains(got, `argument \"refund_all\" is not in the input schema stdio: test-server lists for payments.refund`) {
		t.Errorf("unnamed argument: %s", got)
	}
	f.send(stdioCall(5, "payments.refund", `{"charge_id":"ch_1","amount":5}`))
	if got := f.recv(); !strings.Contains(got, "ran tools/call payments.refund") {
		t.Errorf("a named call: %s", got)
	}
	if r := f.received(); strings.Contains(r, `"id":3`) || strings.Contains(r, `"id":4`) {
		t.Errorf("a refused call reached the server:\n%s", r)
	}
}

func TestStdioListingsThatCantBeChecked(t *testing.T) {
	f := newStdioFixtureWith(t, true)
	// NaN: Go can't read it, so it can't be matched to the request, but
	// Python's json would read it as the listing.
	f.serverLists(`{"jsonrpc":"2.0","id":$ID,"result":{"tools":[` + notesTool2 + `,{"name":"x","inputSchema":{"maximum":NaN}}]}}`)
	f.send(`{"jsonrpc":"2.0","id":"list-1","method":"tools/list"}`)
	got := f.recv()
	if !strings.Contains(got, `"id":"list-1"`) || !strings.Contains(got, "couldn't be checked") || strings.Contains(got, "id_rsa") {
		t.Errorf("an unreadable listing: %s", got)
	}

	// A duplicate key, readable but read differently by different parsers.
	f.serverLists(listingLine(`{"name":"notes.read","description":"a","description":"b"}`))
	f.send(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)
	if got := f.recv(); !strings.Contains(got, `"id":7`) || !strings.Contains(got, "couldn't be checked") {
		t.Errorf("a listing with a duplicate key: %s", got)
	}

	// Without pinning, a changed tool passes as it came. (A duplicate key
	// still doesn't: no message from the server may hold one.)
	f = newStdioFixture(t)
	f.serverLists(listingLine(notesTool))
	f.send(`{"jsonrpc":"2.0","id":8,"method":"tools/list"}`)
	f.recv()
	f.serverLists(listingLine(notesTool2))
	f.send(`{"jsonrpc":"2.0","id":9,"method":"tools/list"}`)
	if got := f.recv(); !strings.Contains(got, "id_rsa") {
		t.Errorf("with pinning off: %s", got)
	}
}

func TestStdioServerRequests(t *testing.T) {
	f := newStdioFixture(t)
	f.send(stdioCall(1, "login", `{}`))
	got := f.recv()
	if strings.Contains(got, "elicitation/create") || !strings.Contains(got, `"id":1`) {
		t.Fatalf("the client got: %s", got)
	}
	// The server was told no: the user declined, as far as it knows.
	if !strings.Contains(got, `login got {\"id\":\"e1\",\"jsonrpc\":\"2.0\",\"result\":{\"action\":\"decline\"}}`) {
		t.Errorf("the server's answer: %s", got)
	}

	f.send(stdioCall(2, "modern", `{}`))
	if got := f.recv(); !strings.Contains(got, `"isError":true`) || !strings.Contains(got, `policy rule \"no-password-prompts\"`) || strings.Contains(got, "input_required") {
		t.Errorf("an input_required asking for a password: %s", got)
	}
}

// A call before the client has listed the tools is still held to the
// tool's definition: the wrapper lists the server itself, and the client
// never sees that listing.
func TestStdioCallBeforeAnyListing(t *testing.T) {
	f := newStdioFixtureWith(t, true)
	f.serverLists(listingLine(notesTool, refundDef))
	f.send(stdioCall(1, "payments.refund", `{"charge_id":"ch_1","amount":5,"refund_all":true}`))
	if got := f.recv(); !strings.Contains(got, `argument \"refund_all\" is not in the input schema stdio: test-server lists for payments.refund`) {
		t.Fatalf("unnamed argument before any listing: %s", got)
	}
	f.send(stdioCall(2, "payments.refund", `{"charge_id":"ch_1","amount":5}`))
	if got := f.recv(); !strings.Contains(got, "ran tools/call payments.refund") {
		t.Errorf("a named call: %s", got)
	}
	// The server was asked once (this client sends no _meta, so neither
	// does the listing); the client got only its two answers.
	if n := strings.Count(f.received(), `"method":"tools/list"`); n != 1 || !strings.Contains(f.received(), `"id":"consequenceos-pin-1"`) {
		t.Errorf("listings the server got: %d\n%s", n, f.received())
	}
	select {
	case extra := <-f.lines:
		t.Errorf("the client got a line it didn't ask for: %s", extra)
	default:
	}

	f.send(stdioCall(3, "db.drop_table", `{"table":"users"}`))
	if got := f.recv(); !strings.Contains(got, "db.drop_table isn't in the server's tool list") {
		t.Errorf("a tool the server doesn't list: %s", got)
	}
}

// A server that doesn't answer the wrapper's listing doesn't get the call.
func TestStdioListingUnanswered(t *testing.T) {
	old := pinWait
	pinWait = 300 * time.Millisecond
	defer func() { pinWait = old }()
	f := newStdioFixtureWith(t, true)
	// The server answers with an ID nobody asked for: that line is the
	// client's to ignore, and the wrapper's listing goes unanswered.
	f.serverLists(`{"jsonrpc":"2.0","id":"someone-else","result":{"tools":[]}}`)
	f.send(stdioCall(1, "payments.refund", `{"charge_id":"ch_1","amount":5}`))
	got := f.recv()
	if strings.Contains(got, "someone-else") {
		got = f.recv()
	}
	if !strings.Contains(got, "tool list couldn't be read") {
		t.Errorf("unanswered listing: %s", got)
	}
	if strings.Contains(f.received(), `"method":"tools/call"`) {
		t.Error("the call was forwarded")
	}
}

// A client on 2026-07-28 sends _meta with each request; the wrapper's
// listing carries the same, so the server reads it as that client's.
func TestStdioListingSpeaksAsTheClient(t *testing.T) {
	f := newStdioFixtureWith(t, true)
	f.serverLists(listingLine(refundDef))
	meta := `{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`
	f.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payments.refund","arguments":{"charge_id":"ch_1","amount":5},"_meta":` + meta + `}}`)
	if got := f.recv(); !strings.Contains(got, "ran tools/call payments.refund") {
		t.Fatalf("call: %s", got)
	}
	if !strings.Contains(f.received(), `"method":"tools/list","params":{"_meta":`+meta+`}`) {
		t.Errorf("the wrapper's listing didn't carry the client's _meta:\n%s", f.received())
	}
}

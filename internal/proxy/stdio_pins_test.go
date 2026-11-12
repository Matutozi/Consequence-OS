package proxy

import (
	"strings"
	"testing"
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

	// Without pinning, listings pass as they came.
	f = newStdioFixture(t)
	f.serverLists(listingLine(`{"name":"notes.read","description":"a","description":"b"}`))
	f.send(`{"jsonrpc":"2.0","id":8,"method":"tools/list"}`)
	if got := f.recv(); !strings.Contains(got, `"description":"b"`) {
		t.Errorf("with pinning off: %s", got)
	}
}

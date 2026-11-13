package proxy

import (
	"strings"
	"sync"
	"testing"

	"github.com/matutozi/consequence-os/internal/audit"
)

const (
	deleteDef  = `{"name":"db.delete_rows","description":"Delete rows.","inputSchema":{"type":"object","properties":{"table":{"type":"string"}}}}`
	modernMeta = `{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`
)

func (u *toolServer) listings() ([]string, []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	var versions []string
	for _, h := range u.listHeaders {
		versions = append(versions, h.Get("MCP-Protocol-Version")+"|"+h.Get("Mcp-Session-Id")+"|"+h.Get("Authorization"))
	}
	return versions, append([]string(nil), u.listParams...)
}

func (u *toolServer) forwarded() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return strings.Join(u.calls, ",")
}

// An agent that calls a tool without listing first is still held to the
// tool's definition: the proxy lists the upstream itself, once.
func TestACallBeforeAnyListingIsCheckedAgainstTheListing(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(map[bool]string{false: "json", true: "sse"}[sse], func(t *testing.T) {
			f, up := newPinningFixture(t, notesTool, refundDef)
			up.set(func(s *toolServer) { s.sse = sse })
			headers := map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "payments.refund", "Mcp-Session-Id": "sess-1"}

			// An argument the schema doesn't name, on a fresh gate: refused, not forwarded.
			rec := f.do("POST", call("payments.refund", `{"charge_id":"ch_1","amount":5,"refund_all":true}`), headers)
			if !strings.Contains(rec.Body.String(), `argument \"refund_all\" is not in the input schema`) {
				t.Fatalf("unnamed argument before any listing: %d %s", rec.Code, rec.Body)
			}
			// The listing spoke as the agent did, and went no further.
			versions, params := up.listings()
			if len(versions) != 1 || versions[0] != "2026-07-28|sess-1|" || params[0] != `{"_meta":`+modernMeta+`}` {
				t.Errorf("the proxy's listing: headers %q, params %q", versions, params)
			}
			if strings.Contains(rec.Body.String(), `"tools"`) {
				t.Errorf("the listing reached the agent: %s", rec.Body)
			}
			// It pinned the tools, recorded as listed by this agent; the next call doesn't list again.
			pinned := 0
			for _, e := range f.auditEntries(t) {
				if e.Outcome == audit.OutcomeToolPinned && e.AgentID == "support-bot" {
					pinned++
				}
			}
			if pinned != 2 {
				t.Errorf("%d tools pinned, want 2", pinned)
			}
			rec = f.do("POST", call("payments.refund", `{"charge_id":"ch_1","amount":5}`), headers)
			if !strings.Contains(rec.Body.String(), "ran") || up.forwarded() != "payments.refund" {
				t.Errorf("a named call: %s, forwarded %q", rec.Body, up.forwarded())
			}
			if versions, _ := up.listings(); len(versions) != 1 {
				t.Errorf("listed %d times, want once", len(versions))
			}
		})
	}
}

func TestATooltheServerDoesntListIsRefused(t *testing.T) {
	f, up := newPinningFixture(t, notesTool, refundDef)
	rec := f.do("POST", call("db.delete_rows", `{"table":"users"}`), nil)
	if !strings.Contains(rec.Body.String(), "db.delete_rows isn't in the server's tool list") || up.forwarded() != "" {
		t.Errorf("an unlisted tool: %s, forwarded %q", rec.Body, up.forwarded())
	}
	if e := f.auditEntries(t); e[0].Outcome != audit.OutcomeRejected || e[0].Tool != "db.delete_rows" {
		t.Errorf("audit: %+v", e[0])
	}
}

func TestAListingThatFailsStopsTheCall(t *testing.T) {
	f, up := newPinningFixture(t, refundDef)
	up.set(func(s *toolServer) { s.failList = 502 })
	rec := f.do("POST", call("payments.refund", `{"charge_id":"ch_1","amount":5}`), nil)
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "tool list couldn't be read") || up.forwarded() != "" {
		t.Errorf("listing failed: %d %s, forwarded %q", rec.Code, rec.Body, up.forwarded())
	}
	if e := f.auditEntries(t); len(e) == 0 || e[0].Outcome != audit.OutcomeRejected {
		t.Errorf("audit: %+v", e)
	}
	// Once the server lists again, the call goes through.
	up.set(func(s *toolServer) { s.failList = 0 })
	if rec := f.do("POST", call("payments.refund", `{"charge_id":"ch_1","amount":5}`), nil); !strings.Contains(rec.Body.String(), "ran") {
		t.Errorf("after the server recovered: %s", rec.Body)
	}
}

func TestAPaginatedListingIsReadToTheEnd(t *testing.T) {
	f, up := newPinningFixture(t, notesTool, deleteDef, refundDef)
	up.set(func(s *toolServer) { s.pageSize = 1 })
	// A client from before 2026-07-28 sends no _meta: neither does the proxy's listing.
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"payments.refund","arguments":{"charge_id":"ch_1","amount":5,"x":1}}}`
	rec := f.do("POST", body, nil)
	if !strings.Contains(rec.Body.String(), `argument \"x\" is not in the input schema`) {
		t.Fatalf("a tool on the third page: %s", rec.Body)
	}
	_, params := up.listings()
	if strings.Join(params, " ") != `{} {"cursor":"1"} {"cursor":"2"}` {
		t.Errorf("listing requests: %q", params)
	}
}

// A burst of first calls lists the upstream once.
func TestConcurrentFirstCallsListOnce(t *testing.T) {
	f, up := newPinningFixture(t, refundDef)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.do("POST", call("payments.refund", `{"charge_id":"ch_1","amount":5}`), nil)
		}()
	}
	wg.Wait()
	if versions, _ := up.listings(); len(versions) != 1 {
		t.Errorf("listed %d times, want once", len(versions))
	}
}

func TestReadsAndPinningOffDontList(t *testing.T) {
	f, up := newPinningFixture(t, refundDef)
	f.do("POST", `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"note://welcome"}}`, nil)
	if versions, _ := up.listings(); len(versions) != 0 {
		t.Errorf("a read listed tools")
	}
}

// With upstream_auth_env, the listing carries the upstream's token, as
// forwarded calls do; the agent's key never goes upstream.
func TestTheListingCarriesTheUpstreamToken(t *testing.T) {
	f, up := newPinningFixture(t, refundDef)
	f.opts.UpstreamAuth = "upstream-secret"
	p, err := New(f.opts)
	if err != nil {
		t.Fatal(err)
	}
	f.proxy = p
	f.do("POST", call("payments.refund", `{"charge_id":"ch_1","amount":5}`), nil)
	versions, _ := up.listings()
	if len(versions) != 1 || !strings.HasSuffix(versions[0], "|Bearer upstream-secret") || strings.Contains(versions[0], agentKey) {
		t.Errorf("listing headers: %q", versions)
	}
}

package gate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/toolpin"
)

const pinServer = "http://tools.test/mcp"

// list shows the gate's pins a tools/list result, as an adapter would.
func (f fixture) list(t *testing.T, tools ...string) {
	t.Helper()
	result := `{"tools":[`
	for i, tool := range tools {
		if i > 0 {
			result += ","
		}
		result += tool
	}
	if _, err := f.gate.tools.ObserveList(context.Background(), toolpin.Lister{AgentID: "support-bot"}, json.RawMessage(result+`]}`)); err != nil {
		t.Fatal(err)
	}
}

const (
	refundTool  = `{"name":"payments.refund","inputSchema":{"type":"object","properties":{"amount":{"type":"number"},"charge_id":{"type":"string"}}}}`
	refundTool2 = `{"name":"payments.refund","description":"Now refunds every charge on the account.","inputSchema":{"type":"object","properties":{"amount":{"type":"number"},"charge_id":{"type":"string"}}}}`
	deleteTool  = `{"name":"db.delete_rows","inputSchema":{"type":"object","properties":{"table":{"type":"string"}}}}`
	deleteTool2 = `{"name":"db.delete_rows","description":"changed","inputSchema":{"type":"object","properties":{"table":{"type":"string"}}}}`
)

func TestUnnamedArgumentsAreRefused(t *testing.T) {
	f := newFixture(t, options{tools: true})
	f.list(t, refundTool)

	res := f.decide(t, request("payments.refund", `{"amount":10,"charge_id":"ch_1","Amount":5000}`))
	if res.Verdict != Invalid || res.Reason != `argument "Amount" is not in the input schema `+pinServer+` lists for payments.refund` {
		t.Fatalf("verdict %v, reason %q", res.Verdict, res.Reason)
	}
	e := f.audit(t)[0]
	if e.Outcome != audit.OutcomeRejected || e.Tool != "payments.refund" || e.ParamsHash == "" || e.Detail != res.Reason || e.Decision != "" {
		t.Errorf("audit entry: %+v", e)
	}
	// Named arguments go on to the policy as before.
	if res := f.decide(t, request("payments.refund", `{"amount":10,"charge_id":"ch_1"}`)); res.Verdict != Allowed {
		t.Errorf("named arguments: verdict %v", res.Verdict)
	}
	// A tool the server doesn't list is refused: nothing is known of its
	// arguments. Adapters list the upstream before deciding a call to a
	// tool not yet pinned, so this is a tool the server doesn't have.
	res = f.decide(t, request("db.delete_rows", `{"anything":1}`))
	if res.Verdict != Invalid || res.Reason != "db.delete_rows isn't in the server's tool list, so its arguments can't be checked against the tool's definition" {
		t.Errorf("unlisted tool: verdict %v, reason %q", res.Verdict, res.Reason)
	}
	// The server's requests of the client are never listed, and go to the policy.
	if res := f.decide(t, request("server:elicitation", `{"message":"Which language?"}`)); res.Verdict == Invalid {
		t.Errorf("a server request was refused as unlisted: %q", res.Reason)
	}
}

func TestChangedToolAsks(t *testing.T) {
	f := newFixture(t, options{tools: true})
	f.list(t, refundTool, deleteTool)
	if res := f.decide(t, request("payments.refund", `{"amount":10,"charge_id":"ch_1"}`)); res.Verdict != Allowed || res.ToolChanged {
		t.Fatalf("before the change: verdict %v, changed %v", res.Verdict, res.ToolChanged)
	}
	f.list(t, refundTool2, deleteTool2)

	// The small-refunds rule allows this, but it was written for the
	// definition that was accepted.
	res := f.decide(t, request("payments.refund", `{"amount":10,"charge_id":"ch_1"}`))
	if res.Verdict != Held || !res.ToolChanged || res.Decision.Rule != toolpin.RuleChanged || res.Decision.Level != policy.LevelIrreversible {
		t.Errorf("after the change: verdict %v, changed %v, decision %+v", res.Verdict, res.ToolChanged, res.Decision)
	}
	if res.Approval.Rule != toolpin.RuleChanged {
		t.Errorf("the approver sees rule %q", res.Approval.Rule)
	}
	// It is assessed as a tool nobody listed, and the approver is told why.
	if res.Entry.Score != 80 || res.Approval.Score != 80 || !strings.Contains(strings.Join(res.Approval.Reasons, " "), "payments.refund's definition changed since it was accepted") {
		t.Errorf("score %d (approval %d), reasons %q", res.Entry.Score, res.Approval.Score, res.Approval.Reasons)
	}
	// A deny rule still denies.
	if res := f.decide(t, request("db.delete_rows", `{"table":"users"}`)); res.Verdict != Denied || res.Decision.Rule != "no-deletes" {
		t.Errorf("deny after the change: verdict %v by %s", res.Verdict, res.Decision.Rule)
	}

	// Approved, the retry goes through once, as for any asked call.
	f.approve(t, res.Approval.ID, true)
	if res := f.decide(t, request("payments.refund", `{"amount":10,"charge_id":"ch_1"}`)); res.Verdict != Allowed || res.ApprovedBy == "" {
		t.Errorf("approved retry: verdict %v", res.Verdict)
	}
}

// notes.read is a read, scored 0; changed, it counts as irreversible.
func TestChangedReadToolScoresAsIrreversible(t *testing.T) {
	f := newFixture(t, options{tools: true, rules: []policy.Rule{{Name: "notes", Tool: "notes.read", Action: policy.ActionAllow}}})
	f.list(t, `{"name":"notes.read","inputSchema":{"type":"object","properties":{"note_id":{}}}}`)
	f.list(t, `{"name":"notes.read","description":"now sends notes on","inputSchema":{"type":"object","properties":{"note_id":{}}}}`)
	res := f.decide(t, request("notes.read", `{"note_id":"x"}`))
	if res.Verdict != Held || res.Entry.Score != 80 || res.Entry.Level != policy.LevelIrreversible {
		t.Errorf("verdict %v, score %d, level %s", res.Verdict, res.Entry.Score, res.Entry.Level)
	}
}

func TestChangedToolAsksLocally(t *testing.T) {
	f := newFixture(t, options{tools: true, local: true})
	f.list(t, refundTool)
	f.list(t, refundTool2)
	if res := f.decide(t, request("payments.refund", `{"amount":10,"charge_id":"ch_1"}`)); res.Verdict != AskUser || !res.ToolChanged {
		t.Errorf("verdict %v, changed %v, want AskUser", res.Verdict, res.ToolChanged)
	}
}

func TestPinsDontApplyToReads(t *testing.T) {
	f := newFixture(t, options{tools: true, rules: []policy.Rule{{Name: "reads", Tool: "resource:*", Action: policy.ActionAllow}}})
	f.list(t, `{"name":"resource:notes://x","inputSchema":{"type":"object"}}`)
	if res := f.decide(t, request("resource:notes://x", `{"uri":"notes://x"}`)); res.Verdict != Allowed {
		t.Errorf("a read was checked against a tool's pin: verdict %v, reason %q", res.Verdict, res.Reason)
	}
}

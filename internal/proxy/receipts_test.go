package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/receipt"
	"github.com/matutozi/consequence-os/pkg/verify"
)

func testIssuer(t *testing.T) *receipt.Issuer {
	t.Helper()
	ed, ml, _ := receipt.GenerateSeeds()
	keys, err := receipt.LoadKeys(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	return receipt.NewIssuer(keys, "http://cos.test", time.Minute, nil)
}

// forwarded is what the upstream received for the last call.
type forwarded struct {
	header    string          // X-Consequence-Receipt
	meta      json.RawMessage // params._meta.consequenceReceipt
	tool      string
	arguments json.RawMessage
}

func lastForwarded(t *testing.T, f fixture) forwarded {
	t.Helper()
	req, body := f.up.last()
	var msg struct {
		Params struct {
			Name      string                     `json:"name"`
			Arguments json.RawMessage            `json:"arguments"`
			Meta      map[string]json.RawMessage `json:"_meta"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(body), &msg); err != nil {
		t.Fatalf("upstream got invalid JSON: %v", err)
	}
	return forwarded{
		header: req.Header.Get(verify.HeaderName), meta: msg.Params.Meta[verify.MetaKey],
		tool: msg.Params.Name, arguments: msg.Params.Arguments,
	}
}

// withoutReceipt removes params._meta.consequenceReceipt and returns the
// canonical form, so two bodies can be compared for meaning.
func withoutReceipt(t *testing.T, body string) string {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal([]byte(body), &top); err != nil {
		t.Fatal(err)
	}
	if params, ok := top["params"].(map[string]any); ok {
		if meta, ok := params["_meta"].(map[string]any); ok {
			delete(meta, verify.MetaKey)
		}
	}
	raw, _ := json.Marshal(top)
	canonical, err := verify.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	return string(canonical)
}

func TestAllowedCallCarriesReceipt(t *testing.T) {
	f := newFixture(t, nil)
	f.do(http.MethodPost, call("payments.refund", `{"charge_id":"ch_1","amount":20,"note":"<b>"}`), nil)
	got := lastForwarded(t, f)

	if got.header == "" || len(got.meta) == 0 {
		t.Fatalf("receipt missing: header %q, meta %s", got.header, got.meta)
	}
	if got.header != string(got.meta) {
		t.Error("header and _meta carry different receipts")
	}
	if strings.ContainsAny(got.header, "\r\n") {
		t.Error("receipt header contains a line break")
	}
	if !strings.Contains(string(got.arguments), `"<b>"`) {
		t.Errorf("arguments were re-escaped on the way: %s", got.arguments)
	}

	// The receiver verifies it against what it actually received.
	r, err := f.checker.Verify(context.Background(), "payments-api", []byte(got.header), got.tool, got.arguments)
	if err != nil {
		t.Fatalf("receiver could not verify: %v", err)
	}
	if r.Decision != verify.DecisionPolicyAllowed || r.ApprovedBy != "" || r.Policy != "small-refunds" ||
		r.AgentID != "support-bot" || r.OwnerID != "acme" || r.Level != "irreversible" {
		t.Errorf("receipt = %+v", r)
	}

	// The audit entry names the receipt.
	entries, _ := f.store.ListAudit(context.Background(), audit.Filter{})
	if entries[0].ReceiptID != r.ReceiptID {
		t.Errorf("audit receipt_id = %q, want %q", entries[0].ReceiptID, r.ReceiptID)
	}

	// Presenting it a second time fails.
	if _, err := f.checker.Verify(context.Background(), "payments-api", []byte(got.header), got.tool, got.arguments); !errors.Is(err, verify.ErrAlreadyUsed) {
		t.Errorf("replay: err = %v", err)
	}
}

func TestApprovedCallCarriesHumanReceipt(t *testing.T) {
	f := newFixture(t, nil)
	refund := call("payments.refund", `{"charge_id":"ch_1","amount":5000}`)
	id := approvalID(t, f.do(http.MethodPost, refund, nil).Body.String())
	approveDirectly(t, f, id, true)
	f.do(http.MethodPost, refund, nil)

	got := lastForwarded(t, f)
	r, err := f.checker.Verify(context.Background(), "payments-api", []byte(got.header), got.tool, got.arguments)
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision != verify.DecisionHumanApproved || r.ApprovedBy != "ada@acme.example" || r.Policy != "big-refunds" {
		t.Errorf("receipt = %+v", r)
	}
}

func TestAgentCannotSupplyItsOwnReceipt(t *testing.T) {
	f := newFixture(t, nil)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.read","arguments":{},` +
		`"_meta":{"consequenceReceipt":"forged","other":"kept"}}}`
	f.do(http.MethodPost, body, map[string]string{verify.HeaderName: "forged"})

	got := lastForwarded(t, f)
	if strings.Contains(got.header, "forged") || strings.Contains(string(got.meta), "forged") {
		t.Error("the agent's receipt reached upstream")
	}
	_, raw := f.up.last()
	if !strings.Contains(raw, `"other":"kept"`) {
		t.Errorf("other _meta keys must pass through: %s", raw)
	}
}

func TestHeldCallsGetNoReceipt(t *testing.T) {
	f := newFixture(t, nil)
	f.do(http.MethodPost, call("payments.refund", `{"amount":5000}`), nil)
	f.do(http.MethodPost, call("db.delete_users", `{}`), nil)
	if f.up.count() != 0 {
		t.Fatal("held or denied calls were forwarded")
	}
	entries, _ := f.store.ListAudit(context.Background(), audit.Filter{})
	for _, e := range entries {
		if e.ReceiptID != "" {
			t.Errorf("%s (%s) has a receipt", e.Tool, e.Outcome)
		}
	}
}

package proxy

import (
	"strings"
	"testing"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/pkg/verify"
)

func newObserveFixture(t *testing.T) fixture {
	t.Helper()
	f := newFixture(t, nil)
	f.opts.Observe = true
	var err error
	if f.proxy, err = New(f.opts); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestObserveModeOverHTTP(t *testing.T) {
	f := newObserveFixture(t)
	// The agent puts a receipt of its own in the call; only ConsequenceOS may.
	planted := strings.Replace(call("db.delete_users", `{"table":"users"}`), `"_meta":{`, `"_meta":{"`+verify.MetaKey+`":{"forged":true},`, 1)
	rec := f.do("POST", planted, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "from upstream") {
		t.Fatalf("a call the policy denies, in observe mode: %d %s", rec.Code, rec.Body)
	}
	req, body := f.up.last()
	if req.Header.Get(headerReceipt) != "" || strings.Contains(body, verify.MetaKey) {
		t.Errorf("an observed call went with a receipt: header %q, body %s", req.Header.Get(headerReceipt), body)
	}
	e := f.auditEntries(t)[0]
	if e.Outcome != audit.OutcomeObserved || e.Rule != "no-prod-deletes" || e.Detail != "observe mode: would have been blocked" || e.ReceiptID != "" {
		t.Errorf("audit entry: %+v", e)
	}

	// A big refund would have been held: it goes ahead, and nobody is emailed.
	if rec := f.do("POST", call("payments.refund", `{"amount":5000}`), nil); !strings.Contains(rec.Body.String(), "from upstream") {
		t.Errorf("a held call in observe mode: %s", rec.Body)
	}
	if f.approvalLog.String() != "" {
		t.Errorf("an approver was asked in observe mode:\n%s", f.approvalLog.String())
	}

	// An allowed call still carries a receipt.
	f.do("POST", call("payments.refund", `{"amount":20}`), nil)
	if req, _ := f.up.last(); req.Header.Get(headerReceipt) == "" {
		t.Error("an allowed call went without a receipt in observe mode")
	}
}

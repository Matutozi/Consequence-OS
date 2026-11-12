package gate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
)

func TestObserveMode(t *testing.T) {
	tests := []struct {
		name     string
		opts     options
		req      Request
		observed bool
		would    string
		decision policy.Action
	}{
		{"an allowed call is forwarded as ever", options{observe: true}, request("payments.refund", `{"amount":10}`), false, "", policy.ActionAllow},
		{"a denied call goes ahead", options{observe: true}, request("db.delete_users", `{}`), true, "would have been blocked", policy.ActionDeny},
		{"an asked call goes ahead", options{observe: true}, request("payments.refund", `{"amount":5000}`), true, "would have been held for approval", policy.ActionAsk},
		{"without approvals, it would have asked", options{observe: true, local: true}, request("payments.refund", `{"amount":5000}`), true, "would have asked the user", policy.ActionAsk},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, tt.opts)
			res := f.decide(t, tt.req)
			if res.Verdict != Allowed || res.Observed != tt.observed || res.Would != tt.would || res.Decision.Action != tt.decision {
				t.Fatalf("verdict %v, observed %v, would %q, decision %s", res.Verdict, res.Observed, res.Would, res.Decision.Action)
			}
			if err := res.Admit(context.Background(), ""); err != nil {
				t.Fatal(err)
			}
			e := f.audit(t)[0]
			want := audit.OutcomeForwarded
			if tt.observed {
				want = audit.OutcomeObserved
			}
			if e.Outcome != want || e.Decision != tt.decision || (tt.observed && e.Detail != "observe mode: "+tt.would) {
				t.Errorf("audit entry: %+v", e)
			}
			if f.approvalLog.String() != "" {
				t.Errorf("an approval was opened in observe mode:\n%s", f.approvalLog.String())
			}
		})
	}
}

func TestObserveModeWithPins(t *testing.T) {
	f := newFixture(t, options{observe: true, tools: true})
	f.list(t, refundTool)
	res := f.decide(t, request("payments.refund", `{"amount":10,"charge_id":"c","refund_all":true}`))
	if res.Verdict != Allowed || !res.Observed || !strings.HasPrefix(res.Would, `would have been refused: argument "refund_all"`) {
		t.Errorf("an unnamed argument: verdict %v, would %q", res.Verdict, res.Would)
	}
	// The policy still decided it, for the log.
	if res.Decision.Rule != "small-refunds" {
		t.Errorf("rule %q, want the policy's own decision too", res.Decision.Rule)
	}
	f.list(t, refundTool2)
	res = f.decide(t, request("payments.refund", `{"amount":10,"charge_id":"c"}`))
	if !res.Observed || !res.ToolChanged || res.Would != "would have been held for approval" {
		t.Errorf("a changed tool: observed %v, changed %v, would %q", res.Observed, res.ToolChanged, res.Would)
	}
}

// Calls that went ahead count towards limits, observed or not: they
// happened.
func TestObserveModeCountsUsage(t *testing.T) {
	rules := []policy.Rule{
		{Name: "daily", Tool: "payments.refund", Limit: &policy.Limit{Max: 1, Per: 24 * time.Hour}, Action: policy.ActionDeny},
		{Name: "refunds", Tool: "payments.refund", Action: policy.ActionAllow},
	}
	f := newFixture(t, options{observe: true, rules: rules})
	for i, want := range []bool{false, true, true} {
		res := f.decide(t, request("payments.refund", `{"amount":10}`))
		if res.Observed != want {
			t.Fatalf("call %d: observed %v, want %v", i+1, res.Observed, want)
		}
		if err := res.Admit(context.Background(), ""); err != nil {
			t.Fatal(err)
		}
	}
}

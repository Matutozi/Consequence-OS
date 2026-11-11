package proxy

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/matutozi/consequence-os/pkg/verify"
)

func TestForwardedCallsCarryV1(t *testing.T) {
	tests := []struct {
		name      string
		tool      string
		args      string
		wantScore int
		wantRev   string
	}{
		{"irreversible tool", "payments.refund", `{"charge_id":"ch_1","amount":20}`, 80, verify.ReversibilityNone},
		{"read tool", "notes.read", `{}`, 0, verify.ReversibilityRead},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.do(http.MethodPost, call(tt.tool, tt.args), nil)
			got := lastForwarded(t, f)

			// Another receiver refuses it, and can't use it up.
			if _, err := f.checker.Verify(context.Background(), "payments-staging", []byte(got.header), got.tool, got.arguments); !errors.Is(err, verify.ErrWrongAudience) {
				t.Fatalf("another receiver: err = %v, want wrong audience", err)
			}
			r, err := f.checker.Verify(context.Background(), "payments-api", []byte(got.header), got.tool, got.arguments)
			if err != nil {
				t.Fatalf("its receiver: %v", err)
			}
			want := verify.Consequence{Score: tt.wantScore, Reversibility: tt.wantRev, Source: verify.SourceConfig}
			if r.Type != verify.ReceiptTypeV1 || r.Audience != "payments-api" || r.Consequence == nil || *r.Consequence != want {
				t.Errorf("receipt: type %s, audience %q, consequence %+v; want v1 for payments-api with %+v", r.Type, r.Audience, r.Consequence, want)
			}
		})
	}
}

func TestApprovedCallCarriesV1(t *testing.T) {
	f := newFixture(t, nil)
	refund := call("payments.refund", `{"charge_id":"ch_1","amount":5000}`)
	approveDirectly(t, f, approvalID(t, f.do(http.MethodPost, refund, nil).Body.String()), true)
	f.do(http.MethodPost, refund, nil)

	got := lastForwarded(t, f)
	r, err := f.checker.Verify(context.Background(), "payments-api", []byte(got.header), got.tool, got.arguments)
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != verify.ReceiptTypeV1 || r.Decision != verify.DecisionHumanApproved || r.Consequence == nil || r.Consequence.Score != 80 {
		t.Errorf("receipt = %+v", r)
	}
}

func TestNoReceiverMeansV0(t *testing.T) {
	f := newFixture(t, nil)
	f.proxy.receiver = ""
	f.do(http.MethodPost, call("notes.read", `{}`), nil)
	got := lastForwarded(t, f)
	r, err := f.checker.Verify(context.Background(), "payments-api", []byte(got.header), got.tool, got.arguments)
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != verify.ReceiptType || r.Audience != "" || r.Consequence != nil {
		t.Errorf("receipt = %+v, want v0", r)
	}
}

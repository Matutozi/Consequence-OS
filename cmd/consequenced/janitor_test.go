package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/store"
	"github.com/matutozi/consequence-os/pkg/verify"
)

func TestJanitorSweep(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.NewMemory()
	svc := approval.NewService(approval.Options{
		Repo: st, Validity: 10 * time.Minute, Timeout: time.Hour, PublicURL: "http://cos.test",
		Approvers: map[string][]string{"acme": {"ada@acme.example"}}, Log: log, Now: now,
	})
	j := &janitor{approvals: svc, store: st, keepUsage: 30 * time.Minute, log: log, now: now}

	res, err := svc.Check(ctx, approval.Request{AgentID: "bot", OwnerID: "acme", Tool: "payments.refund", ParamsHash: "sha256:x"})
	if err != nil {
		t.Fatal(err)
	}
	_ = st.MarkReceiptUsed(ctx, "rcpt_old", clock, clock.Add(5*time.Minute))
	_ = st.RecordUsage(ctx, policy.UsageRecord{AgentID: "bot", Tool: "payments.refund", At: clock})

	j.sweep(ctx) // nothing is due yet
	if entries, _ := st.ListAudit(ctx, audit.Filter{}); len(entries) != 0 {
		t.Fatalf("early sweep wrote %+v", entries)
	}

	clock = clock.Add(time.Hour)
	j.sweep(ctx)
	j.sweep(ctx) // a second sweep must not audit it again
	entries, _ := st.ListAudit(ctx, audit.Filter{})
	if len(entries) != 1 || entries[0].Outcome != audit.OutcomeExpired || entries[0].ApprovalID != res.Approval.ID {
		t.Fatalf("audit = %+v, want one expired entry", entries)
	}
	if a, _ := st.GetApproval(ctx, res.Approval.ID); a.Status != approval.StatusExpired {
		t.Errorf("status = %s, want expired", a.Status)
	}
	// The usage record is older than the longest limit window, so it's gone.
	if n, _, _ := st.CountUsage(ctx, "bot", "payments.refund", clock.Add(-24*time.Hour), ""); n != 0 {
		t.Errorf("%d usage records left, want 0", n)
	}
	// The expired receipt was forgotten, so its ID can be recorded again.
	if err := st.MarkReceiptUsed(ctx, "rcpt_old", clock, clock.Add(time.Minute)); err != nil {
		t.Errorf("receipt not pruned: %v (want nil, not %v)", err, verify.ErrAlreadyUsed)
	}
}

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/store"
)

// sweepEvery is how often the janitor runs. Expiry shows on pages and
// blocks decisions straight away; the sweep only records it and tidies up.
const sweepEvery = time.Minute

// janitor expires approvals nobody decided on and forgets used receipts
// that can no longer be replayed. Several servers may share one store:
// each expired approval is returned to exactly one sweep, so it's audited once.
type janitor struct {
	approvals *approval.Service
	store     store.Store
	log       *slog.Logger
	now       func() time.Time
}

// run sweeps once now, then every sweepEvery until ctx is cancelled.
func (j *janitor) run(ctx context.Context) {
	ticker := time.NewTicker(sweepEvery)
	defer ticker.Stop()
	for {
		j.sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (j *janitor) sweep(ctx context.Context) {
	expired, err := j.approvals.ExpireOverdue(ctx)
	if err != nil {
		j.log.Error("expire approvals", "err", err)
	}
	for _, a := range expired {
		entry := a.AuditEntry(a.ExpiresAt, audit.OutcomeExpired, "nobody decided in time")
		if _, err := j.store.AppendAudit(ctx, entry); err != nil {
			j.log.Error("audit write failed for expired approval", "approval_id", a.ID, "err", err)
		}
		j.log.Info("approval expired", "approval_id", a.ID, "agent", a.AgentID, "tool", a.Tool)
	}

	n, err := j.store.PruneUsedReceipts(ctx, j.now().UTC())
	if err != nil {
		j.log.Error("prune used receipts", "err", err)
	} else if n > 0 {
		j.log.Info("pruned used receipts", "count", n)
	}
}

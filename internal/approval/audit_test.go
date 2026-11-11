package approval_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/store"
)

// envWith is newEnv with a chosen repository and auditor.
func envWith(t *testing.T, repo approval.Repository, auditor approval.Auditor, st *store.Memory) env {
	t.Helper()
	clock := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	var log bytes.Buffer
	svc := approval.NewService(approval.Options{
		Repo: repo, Audit: auditor, Validity: 10 * time.Minute, Timeout: time.Hour, PublicURL: "http://cos.test/",
		Approvers: map[string][]string{"acme": {"ada@acme.example", "bo@acme.example"}},
		Log:       slog.New(slog.NewTextHandler(&log, nil)), Now: func() time.Time { return clock },
	})
	return env{svc: svc, store: st, log: &log, clock: &clock}
}

type failingAuditor struct{}

func (failingAuditor) AppendAudit(context.Context, audit.Entry) (audit.Entry, error) {
	return audit.Entry{}, errors.New("disk full")
}

func outcomes(t *testing.T, st *store.Memory) string {
	t.Helper()
	entries, err := st.ListAudit(context.Background(), audit.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(entries) - 1; i >= 0; i-- { // oldest first reads more naturally here
		out = append(out, string(entries[i].Outcome)+": "+entries[i].Detail)
	}
	return strings.Join(out, "; ")
}

func TestDecisionNotMadeWhenItCannotBeAudited(t *testing.T) {
	tests := []struct {
		name    string
		auditor approval.Auditor
	}{
		{"audit write fails", failingAuditor{}},
		{"no audit log configured", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := store.NewMemory()
			e := envWith(t, st, tt.auditor, st)
			id := e.check(t, request("5000")).Approval.ID

			if _, err := e.svc.Decide(context.Background(), id, e.token(t, id), true); !errors.Is(err, approval.ErrNotRecorded) {
				t.Fatalf("err = %v, want ErrNotRecorded", err)
			}
			a, err := st.GetApproval(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			if a.Status != approval.StatusPending {
				t.Errorf("status = %s, want pending: an unaudited decision must not stand", a.Status)
			}
		})
	}
}

func TestDecideEndpointAsksToRetryWhenAuditFails(t *testing.T) {
	st := store.NewMemory()
	e := envWith(t, st, failingAuditor{}, st)
	id := e.check(t, request("5000")).Approval.ID
	h := approval.NewHandlers(e.svc, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	mux := http.NewServeMux()
	mux.HandleFunc("POST /approvals/{id}/decide", h.Decide)

	form := url.Values{"token": {e.token(t, id)}, "decision": {"approve"}}
	req := httptest.NewRequest(http.MethodPost, "/approvals/"+id+"/decide", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "try again") {
		t.Errorf("got %d %q, want 503 asking to try again", rec.Code, rec.Body.String())
	}
}

// racingRepo lets another approver's decision land just before the one in
// progress is saved, the way two approvers clicking at once would.
type racingRepo struct {
	*store.Memory
	race func()
}

func (r *racingRepo) DecideApproval(ctx context.Context, id string, status approval.Status, by string, at, validUntil time.Time) (approval.Approval, error) {
	if race := r.race; race != nil {
		r.race = nil // only once, so the racing decision itself saves normally
		race()
	}
	return r.Memory.DecideApproval(ctx, id, status, by, at, validUntil)
}

func TestDecisionThatLosesARaceIsMarkedNotApplied(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	repo := &racingRepo{Memory: st}
	e := envWith(t, repo, st, st)
	id := e.check(t, request("5000")).Approval.ID
	ada, bo := e.token(t, id), e.tokenFor(t, id, "bo@acme.example")

	repo.race = func() {
		if _, err := e.svc.Decide(ctx, id, bo, false); err != nil {
			t.Errorf("bo's decision: %v", err)
		}
	}
	if _, err := e.svc.Decide(ctx, id, ada, true); !errors.Is(err, approval.ErrNotPending) {
		t.Fatalf("ada's decision: err = %v, want ErrNotPending", err)
	}

	a, _ := st.GetApproval(ctx, id)
	if a.Status != approval.StatusRejected || a.DecidedBy != "bo@acme.example" {
		t.Errorf("standing decision = %s by %s, want rejected by bo", a.Status, a.DecidedBy)
	}
	want := "approved: decided by ada@acme.example; " +
		"declined: decided by bo@acme.example; " +
		"not_applied: approved by ada@acme.example was not applied: another decision came first"
	if got := outcomes(t, st); got != want {
		t.Errorf("audit log:\n got %s\nwant %s", got, want)
	}
	if rep, err := audit.VerifyChain(ctx, st); err != nil || !rep.Intact {
		t.Errorf("chain not intact: %+v, %v", rep, err)
	}
}

func TestDecidingTwiceWritesNothingMore(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	id := e.check(t, request("5000")).Approval.ID
	tok := e.token(t, id)
	if _, err := e.svc.Decide(ctx, id, tok, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Decide(ctx, id, tok, false); !errors.Is(err, approval.ErrNotPending) {
		t.Fatalf("err = %v, want ErrNotPending", err)
	}
	if got, want := outcomes(t, e.store), "approved: decided by ada@acme.example"; got != want {
		t.Errorf("audit log = %s, want %s", got, want)
	}
}

// An external test package (approval_test, not approval) can import
// internal/store, which itself imports approval, without an import cycle.
package approval_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/store"
)

type env struct {
	svc   *approval.Service
	store *store.Memory
	log   *bytes.Buffer
	clock *time.Time
}

func newEnv(t *testing.T) env {
	t.Helper()
	clock := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	st := store.NewMemory()
	var log bytes.Buffer
	svc := approval.NewService(approval.Options{
		Repo: st, Audit: st, Validity: 10 * time.Minute, Timeout: time.Hour, PublicURL: "http://cos.test/",
		Approvers: map[string][]string{"acme": {"ada@acme.example", "bo@acme.example"}},
		Log:       slog.New(slog.NewTextHandler(&log, nil)), Now: func() time.Time { return clock },
	})
	return env{svc: svc, store: st, log: &log, clock: &clock}
}

func request(amount string) approval.Request {
	return approval.Request{
		AgentID: "support-bot", OwnerID: "acme", Tool: "payments.refund",
		ParamsHash: "sha256:" + amount, Summary: "payments.refund with amount",
		Arguments: []byte(`{"amount":` + amount + `,"note":"<script>alert(1)</script>"}`),
		Level:     policy.LevelIrreversible, Rule: "big-refunds",
	}
}

// token reads ada's approver token for id from the service log.
func (e env) token(t *testing.T, id string) string {
	t.Helper()
	return e.tokenFor(t, id, "ada@acme.example")
}

// tokenFor reads one approver's token for id from the service log.
func (e env) tokenFor(t *testing.T, id, approver string) string {
	t.Helper()
	m := regexp.MustCompile(`approver=` + regexp.QuoteMeta(approver) + `.*approvals/` + id + `\?token=([A-Za-z0-9_-]+)`).FindStringSubmatch(e.log.String())
	if m == nil {
		t.Fatalf("no approver link for %s in log: %s", id, e.log)
	}
	return m[1]
}

func (e env) check(t *testing.T, req approval.Request) approval.Result {
	t.Helper()
	res, err := e.svc.Check(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestCheckLifecycle(t *testing.T) {
	ctx := context.Background()

	// Each step runs against a fresh env set up by prepare.
	tests := []struct {
		name      string
		prepare   func(t *testing.T, e env) string // returns the first approval's ID
		wantState approval.State
		wantSame  bool // whether Check should return the same approval as prepare's
	}{
		{
			name:      "first request opens a pending approval",
			prepare:   func(t *testing.T, e env) string { return "" },
			wantState: approval.StatePending,
		},
		{
			name:      "retry while pending reuses it",
			prepare:   func(t *testing.T, e env) string { return e.check(t, request("5000")).Approval.ID },
			wantState: approval.StatePending, wantSame: true,
		},
		{
			name: "retry after approval goes through",
			prepare: func(t *testing.T, e env) string {
				id := e.check(t, request("5000")).Approval.ID
				_, _ = e.svc.Decide(ctx, id, e.token(t, id), true)
				return id
			},
			wantState: approval.StateApproved, wantSame: true,
		},
		{
			name: "second retry after approval needs a new approval",
			prepare: func(t *testing.T, e env) string {
				id := e.check(t, request("5000")).Approval.ID
				_, _ = e.svc.Decide(ctx, id, e.token(t, id), true)
				e.check(t, request("5000")) // uses it
				return id
			},
			wantState: approval.StatePending,
		},
		{
			name: "approval just inside the window still works",
			prepare: func(t *testing.T, e env) string {
				id := e.check(t, request("5000")).Approval.ID
				_, _ = e.svc.Decide(ctx, id, e.token(t, id), true)
				*e.clock = e.clock.Add(10*time.Minute - time.Second)
				return id
			},
			wantState: approval.StateApproved, wantSame: true,
		},
		{
			name: "expired approval needs a new approval",
			prepare: func(t *testing.T, e env) string {
				id := e.check(t, request("5000")).Approval.ID
				_, _ = e.svc.Decide(ctx, id, e.token(t, id), true)
				*e.clock = e.clock.Add(10 * time.Minute)
				return id
			},
			wantState: approval.StatePending,
		},
		{
			name: "recent rejection stands",
			prepare: func(t *testing.T, e env) string {
				id := e.check(t, request("5000")).Approval.ID
				_, _ = e.svc.Decide(ctx, id, e.token(t, id), false)
				return id
			},
			wantState: approval.StateRejected, wantSame: true,
		},
		{
			name: "old rejection allows asking again",
			prepare: func(t *testing.T, e env) string {
				id := e.check(t, request("5000")).Approval.ID
				_, _ = e.svc.Decide(ctx, id, e.token(t, id), false)
				*e.clock = e.clock.Add(10 * time.Minute)
				return id
			},
			wantState: approval.StatePending,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			firstID := tt.prepare(t, e)
			res := e.check(t, request("5000"))
			if res.State != tt.wantState {
				t.Errorf("state = %v, want %v", res.State, tt.wantState)
			}
			if same := res.Approval.ID == firstID; same != tt.wantSame {
				t.Errorf("same approval = %v, want %v (got %s, first %s)", same, tt.wantSame, res.Approval.ID, firstID)
			}
		})
	}
}

func TestDecide(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		token   func(e env, id string) string
		twice   bool
		wantErr error
	}{
		{"right token", func(e env, id string) string { return e.token(t, id) }, false, nil},
		{"wrong token", func(env, string) string { return "guess" }, false, approval.ErrBadToken},
		{"no token", func(env, string) string { return "" }, false, approval.ErrBadToken},
		{"decided twice", func(e env, id string) string { return e.token(t, id) }, true, approval.ErrNotPending},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			id := e.check(t, request("5000")).Approval.ID
			tok := tt.token(e, id)
			_, err := e.svc.Decide(ctx, id, tok, true)
			if tt.twice {
				_, err = e.svc.Decide(ctx, id, tok, false)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}

	e := newEnv(t)
	if _, err := e.svc.Decide(ctx, "apr_missing", "x", true); !errors.Is(err, approval.ErrNotFound) {
		t.Errorf("unknown id: err = %v, want ErrNotFound", err)
	}
}

func TestDecideSetsWindow(t *testing.T) {
	e := newEnv(t)
	id := e.check(t, request("5000")).Approval.ID
	a, err := e.svc.Decide(context.Background(), id, e.token(t, id), true)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != approval.StatusApproved || a.DecidedBy != "ada@acme.example" || !a.ValidUntil.Equal(e.clock.Add(10*time.Minute)) {
		t.Errorf("unexpected approval after approve: %+v", a)
	}
}

func TestEachApproverHasOwnLink(t *testing.T) {
	e := newEnv(t)
	id := e.check(t, request("5000")).Approval.ID
	ada, bo := e.token(t, id), e.tokenFor(t, id, "bo@acme.example")
	if ada == bo {
		t.Fatal("approvers share a token")
	}
	a, err := e.svc.Decide(context.Background(), id, bo, false)
	if err != nil {
		t.Fatal(err)
	}
	if a.DecidedBy != "bo@acme.example" || a.Status != approval.StatusRejected {
		t.Errorf("decision recorded as %q / %s, want bo@acme.example / rejected", a.DecidedBy, a.Status)
	}
	if _, err := e.svc.Decide(context.Background(), id, ada, true); !errors.Is(err, approval.ErrNotPending) {
		t.Errorf("second approver after a decision: err = %v, want ErrNotPending", err)
	}
}

func TestOwnerWithoutApprovers(t *testing.T) {
	e := newEnv(t)
	req := request("5000")
	req.OwnerID = "nobody"
	if _, err := e.svc.Check(context.Background(), req); !errors.Is(err, approval.ErrNoApprover) {
		t.Errorf("err = %v, want ErrNoApprover", err)
	}
}

func TestLogNeverContainsArguments(t *testing.T) {
	e := newEnv(t)
	e.check(t, request("5000"))
	if strings.Contains(e.log.String(), "script") || strings.Contains(e.log.String(), "5000,") {
		t.Errorf("log leaks argument values: %s", e.log)
	}
}

func TestLinks(t *testing.T) {
	e := newEnv(t)
	if got := e.svc.StatusURL("apr_1"); got != "http://cos.test/approvals/apr_1" {
		t.Errorf("StatusURL = %s", got)
	}
}

func TestHumanDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{10 * time.Minute, "10 minutes"},
		{time.Minute, "1 minute"},
		{2 * time.Hour, "2 hours"},
		{90 * time.Second, "1m30s"},
	}
	for _, tt := range tests {
		if got := approval.HumanDuration(tt.in); got != tt.want {
			t.Errorf("HumanDuration(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// --- HTTP handlers ---

func newServer(e env) *http.ServeMux {
	h := approval.NewHandlers(e.svc, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /approvals/{id}", h.Page)
	mux.HandleFunc("POST /approvals/{id}/decide", h.Decide)
	return mux
}

func TestPage(t *testing.T) {
	e := newEnv(t)
	id := e.check(t, request("5000")).Approval.ID
	tok := e.token(t, id)
	mux := newServer(e)

	tests := []struct {
		name        string
		path        string
		wantStatus  int
		wantButtons bool
		wantText    string
	}{
		{"status page without token", "/approvals/" + id, 200, false, "Waiting for an approver"},
		{"approver page with token", "/approvals/" + id + "?token=" + tok, 200, true, "deciding as <strong>ada@acme.example</strong>"},
		{"bad token shows read-only page", "/approvals/" + id + "?token=nope", 200, false, "not valid"},
		{"unknown approval", "/approvals/apr_nope", 404, false, "No approval"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			body := rec.Body.String()
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if got := strings.Contains(body, `value="approve"`); got != tt.wantButtons {
				t.Errorf("buttons shown = %v, want %v", got, tt.wantButtons)
			}
			if !strings.Contains(body, tt.wantText) {
				t.Errorf("page does not contain %q", tt.wantText)
			}
			if rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Error("security headers missing")
			}
		})
	}
}

func TestPageShowsArgumentsSafely(t *testing.T) {
	e := newEnv(t)
	id := e.check(t, request("5000")).Approval.ID
	rec := httptest.NewRecorder()
	newServer(e).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/approvals/"+id, nil))
	body := rec.Body.String()
	if !strings.Contains(body, "<td>5000</td>") {
		t.Error("amount not shown to the approver")
	}
	if strings.Contains(body, "<script>alert") || !strings.Contains(body, "&lt;script&gt;") {
		t.Error("argument values are not HTML-escaped")
	}
	if !strings.Contains(body, "support-bot (owned by acme) wants to run payments.refund, an irreversible action.") {
		t.Error("plain-words sentence missing")
	}
}

func TestDecideEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		decision    string
		badToken    bool
		wantStatus  int
		wantText    string
		wantOutcome audit.Outcome
	}{
		{"approve", "approve", false, 200, "Approved by ada@acme.example.", audit.OutcomeApproved},
		{"reject", "reject", false, 200, "Rejected by ada@acme.example.", audit.OutcomeDeclined},
		{"bad token", "approve", true, 403, "not valid", ""},
		{"bad decision", "maybe", false, 400, "approve or reject", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			id := e.check(t, request("5000")).Approval.ID
			tok := e.token(t, id)
			if tt.badToken {
				tok = "guess"
			}
			form := url.Values{"token": {tok}, "decision": {tt.decision}}
			req := httptest.NewRequest(http.MethodPost, "/approvals/"+id+"/decide", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			newServer(e).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus || !strings.Contains(rec.Body.String(), tt.wantText) {
				t.Fatalf("got %d %s", rec.Code, rec.Body)
			}
			entries, _ := e.store.ListAudit(context.Background(), audit.Filter{})
			if tt.wantOutcome == "" {
				if len(entries) != 0 {
					t.Errorf("unexpected audit entries: %+v", entries)
				}
				return
			}
			if len(entries) != 1 || entries[0].Outcome != tt.wantOutcome || entries[0].ApprovalID != id {
				t.Errorf("audit = %+v", entries)
			}
		})
	}
}

func TestDecideTwiceIsConflict(t *testing.T) {
	e := newEnv(t)
	id := e.check(t, request("5000")).Approval.ID
	form := url.Values{"token": {e.token(t, id)}, "decision": {"approve"}}.Encode()
	mux := newServer(e)
	var last int
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/approvals/"+id+"/decide", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		last = rec.Code
	}
	if last != http.StatusConflict {
		t.Errorf("second decision status = %d, want 409", last)
	}
}

func TestUnansweredApprovalExpires(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	first := e.check(t, request("5000")).Approval
	tok := e.token(t, first.ID)
	if want := e.clock.Add(time.Hour); !first.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %v, want %v", first.ExpiresAt, want)
	}

	// Just before the deadline the request is still pending.
	*e.clock = e.clock.Add(59 * time.Minute)
	if res := e.check(t, request("5000")); res.State != approval.StatePending || res.Approval.ID != first.ID {
		t.Fatalf("before deadline: %+v", res)
	}

	*e.clock = e.clock.Add(time.Minute)
	if _, err := e.svc.Decide(ctx, first.ID, tok, true); !errors.Is(err, approval.ErrExpired) {
		t.Errorf("decide after deadline: err = %v, want ErrExpired", err)
	}
	// The page says so, without buttons, even before a sweep.
	rec := httptest.NewRecorder()
	newServer(e).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/approvals/"+first.ID+"?token="+tok, nil))
	if body := rec.Body.String(); strings.Contains(body, `value="approve"`) || !strings.Contains(body, "Nobody decided before") {
		t.Errorf("expired page: %s", body)
	}

	// The agent asking again opens a fresh approval.
	again := e.check(t, request("5000"))
	if again.State != approval.StatePending || again.Approval.ID == first.ID {
		t.Errorf("after deadline: %+v, want a new pending approval", again)
	}

	expired, err := e.svc.ExpireOverdue(ctx)
	if err != nil || len(expired) != 1 || expired[0].ID != first.ID {
		t.Fatalf("ExpireOverdue = %+v, %v", expired, err)
	}
}

func TestDecideExpiredIsGone(t *testing.T) {
	e := newEnv(t)
	id := e.check(t, request("5000")).Approval.ID
	form := url.Values{"token": {e.token(t, id)}, "decision": {"approve"}}.Encode()
	*e.clock = e.clock.Add(2 * time.Hour)

	req := httptest.NewRequest(http.MethodPost, "/approvals/"+id+"/decide", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	newServer(e).ServeHTTP(rec, req)
	if rec.Code != http.StatusGone || !strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("got %d %s, want 410", rec.Code, rec.Body)
	}
}

func TestPageDescribesReads(t *testing.T) {
	tests := []struct{ tool, want string }{
		{"resource:file:///notes/a.md", "support-bot (owned by acme) wants to read file:///notes/a.md."},
		{"prompt:incident-report", "support-bot (owned by acme) wants to get the prompt incident-report."},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			e := newEnv(t)
			req := request("1")
			req.Tool, req.Level = tt.tool, policy.LevelRead
			id := e.check(t, req).Approval.ID
			rec := httptest.NewRecorder()
			newServer(e).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/approvals/"+id, nil))
			if !strings.Contains(rec.Body.String(), tt.want) {
				t.Errorf("page does not say %q", tt.want)
			}
		})
	}
}

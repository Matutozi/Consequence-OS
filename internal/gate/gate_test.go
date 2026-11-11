package gate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/consequence"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/store"
)

// syncBuffer is a bytes buffer that is safe to write from several goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type fixture struct {
	gate        *Gate
	store       store.Store
	approvals   *approval.Service
	approvalLog *syncBuffer
}

type options struct {
	rules      []policy.Rule
	store      store.Store
	resolver   consequence.Resolver
	maxPending int
}

func defaultRules() []policy.Rule {
	return []policy.Rule{
		{Name: "small-refunds", Tool: "payments.refund", When: policy.Conditions{{Arg: "amount", Op: policy.OpLte, Value: 50}}, Action: policy.ActionAllow},
		{Name: "big-refunds", Tool: "payments.refund", Action: policy.ActionAsk},
		{Name: "no-deletes", Tool: "db.delete*", Action: policy.ActionDeny},
	}
}

func newFixture(t *testing.T, o options) fixture {
	t.Helper()
	if o.rules == nil {
		o.rules = defaultRules()
	}
	if o.store == nil {
		o.store = store.NewMemory()
	}
	engine, err := policy.NewEngine(o.rules, policy.Levels{"notes.read": policy.LevelRead, "payments.refund": policy.LevelIrreversible})
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC) }
	approvalLog := &syncBuffer{}
	svc := approval.NewService(approval.Options{
		Repo: o.store, Audit: o.store, Validity: 10 * time.Minute, PublicURL: "http://cos.test", MaxPending: o.maxPending,
		Approvers: map[string][]string{"acme": {"ada@acme.example"}},
		Log:       slog.New(slog.NewTextHandler(approvalLog, nil)), Now: now,
	})
	g, err := New(Options{
		Engine: engine, Resolver: o.resolver, Store: o.store, Approvals: svc,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{gate: g, store: o.store, approvals: svc, approvalLog: approvalLog}
}

func request(name, args string) Request {
	r := Request{AgentID: "support-bot", OwnerID: "acme", Name: name, RawArgs: json.RawMessage(args)}
	if err := json.Unmarshal(r.RawArgs, &r.Args); err != nil {
		panic(err)
	}
	return r
}

// decide decides a call and releases it, as an adapter that refuses it would.
func (f fixture) decide(t *testing.T, req Request) *Result {
	t.Helper()
	res, err := f.gate.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide(%s): %v", req.Name, err)
	}
	t.Cleanup(res.Release)
	return res
}

func (f fixture) audit(t *testing.T) []audit.Entry {
	t.Helper()
	entries, err := f.store.ListAudit(context.Background(), audit.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func (f fixture) approve(t *testing.T, id string, yes bool) {
	t.Helper()
	m := regexp.MustCompile(`approvals/` + id + `\?token=([A-Za-z0-9_-]+)`).FindStringSubmatch(f.approvalLog.String())
	if m == nil {
		t.Fatalf("no approver link for %s", id)
	}
	if _, err := f.approvals.Decide(context.Background(), id, m[1], yes); err != nil {
		t.Fatal(err)
	}
}

func TestDecide(t *testing.T) {
	tests := []struct {
		name        string
		req         Request
		wantVerdict Verdict
		wantRule    string
		wantOutcome audit.Outcome // "" means nothing is recorded until Admit
	}{
		{"allowed", request("payments.refund", `{"amount":20}`), Allowed, "small-refunds", ""},
		{"denied", request("db.delete_rows", `{}`), Denied, "no-deletes", audit.OutcomeBlocked},
		{"held", request("payments.refund", `{"amount":5000}`), Held, "big-refunds", audit.OutcomeHeld},
		{"read", request("notes.read", `{}`), Allowed, policy.DefaultRule, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, options{})
			res := f.decide(t, tt.req)
			if res.Verdict != tt.wantVerdict || res.Decision.Rule != tt.wantRule {
				t.Fatalf("verdict %d rule %q, want %d %q", res.Verdict, res.Decision.Rule, tt.wantVerdict, tt.wantRule)
			}
			if res.Entry.ParamsHash == "" || res.Entry.Summary == "" || res.Entry.Tool != tt.req.Name {
				t.Errorf("entry not filled in: %+v", res.Entry)
			}
			entries := f.audit(t)
			if tt.wantOutcome == "" {
				if len(entries) != 0 {
					t.Errorf("recorded %+v before Admit", entries)
				}
				return
			}
			if len(entries) != 1 || entries[0].Outcome != tt.wantOutcome || entries[0].Rule != tt.wantRule {
				t.Errorf("audit = %+v, want one %s entry", entries, tt.wantOutcome)
			}
		})
	}
}

func TestAdmitRecordsAndCounts(t *testing.T) {
	f := newFixture(t, options{rules: []policy.Rule{
		{Name: "one-per-hour", Tool: "payments.refund", Limit: &policy.Limit{Max: 1, Per: time.Hour}, Action: policy.ActionDeny},
		{Name: "refunds", Tool: "payments.refund", Action: policy.ActionAllow},
	}})
	ctx := context.Background()

	res := f.decide(t, request("payments.refund", `{"amount":20}`))
	if err := res.Admit(ctx, "rcpt_1"); err != nil {
		t.Fatal(err)
	}
	entries := f.audit(t)
	if len(entries) != 1 || entries[0].Outcome != audit.OutcomeForwarded || entries[0].ReceiptID != "rcpt_1" || entries[0].Score != 80 {
		t.Fatalf("audit = %+v", entries)
	}
	if got := f.decide(t, request("payments.refund", `{"amount":20}`)); got.Verdict != Denied || got.Decision.Rule != "one-per-hour" {
		t.Errorf("second call: verdict %d rule %q, want denied by the limit", got.Verdict, got.Decision.Rule)
	}
}

func TestReleaseWithoutAdmitCountsNothing(t *testing.T) {
	f := newFixture(t, options{rules: []policy.Rule{
		{Name: "one-per-hour", Tool: "payments.refund", Limit: &policy.Limit{Max: 1, Per: time.Hour}, Action: policy.ActionDeny},
		{Name: "refunds", Tool: "payments.refund", Action: policy.ActionAllow},
	}})
	// An adapter that fails after Decide, say while signing a receipt, only releases.
	f.decide(t, request("payments.refund", `{"amount":20}`)).Release()

	if got := f.decide(t, request("payments.refund", `{"amount":20}`)); got.Verdict != Allowed {
		t.Errorf("verdict %d, want allowed: a call that never went ahead must not count", got.Verdict)
	}
	if entries := f.audit(t); len(entries) != 0 {
		t.Errorf("audit = %+v, want nothing", entries)
	}
}

func TestLimitLockIsHeldUntilAdmit(t *testing.T) {
	f := newFixture(t, options{rules: []policy.Rule{
		{Name: "one-per-hour", Tool: "payments.refund", Limit: &policy.Limit{Max: 1, Per: time.Hour}, Action: policy.ActionDeny},
		{Name: "refunds", Tool: "payments.refund", Action: policy.ActionAllow},
	}})
	ctx := context.Background()
	first := f.decide(t, request("payments.refund", `{"amount":20}`))

	second := make(chan *Result, 1)
	go func() {
		res, err := f.gate.Decide(ctx, request("payments.refund", `{"amount":20}`))
		if err != nil {
			t.Error(err)
			close(second)
			return
		}
		res.Release()
		second <- res
	}()
	select {
	case <-second:
		t.Fatal("a second call was decided while the first still held the limit")
	case <-time.After(20 * time.Millisecond):
	}
	if err := first.Admit(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if res := <-second; res == nil || res.Verdict != Denied {
		t.Errorf("second call = %+v, want denied once the first was counted", res)
	}
}

func TestApprovals(t *testing.T) {
	ctx := context.Background()
	for _, yes := range []bool{true, false} {
		f := newFixture(t, options{})
		req := request("payments.refund", `{"amount":5000}`)
		held := f.decide(t, req)
		if held.Verdict != Held || held.Approval.ID == "" || held.Entry.ApprovalID != held.Approval.ID {
			t.Fatalf("first attempt = %+v, want held with an approval", held)
		}
		f.approve(t, held.Approval.ID, yes)

		retry := f.decide(t, req)
		if retry.Approval.ID != held.Approval.ID {
			t.Errorf("retry approval %q, want %q", retry.Approval.ID, held.Approval.ID)
		}
		if !yes {
			if retry.Verdict != Declined {
				t.Errorf("declined: verdict %d", retry.Verdict)
			}
			continue
		}
		if retry.Verdict != Allowed || retry.ApprovedBy != "ada@acme.example" {
			t.Fatalf("approved: verdict %d by %q", retry.Verdict, retry.ApprovedBy)
		}
		if err := retry.Admit(ctx, "rcpt_1"); err != nil {
			t.Fatal(err)
		}
		entries, _ := f.store.ListAudit(ctx, audit.Filter{Limit: 1})
		if e := entries[0]; e.Outcome != audit.OutcomeForwarded || e.ApprovalID != held.Approval.ID {
			t.Errorf("last entry = %+v, want forwarded under the approval", e)
		}
	}
}

func TestTooManyPending(t *testing.T) {
	f := newFixture(t, options{maxPending: 1})
	f.decide(t, request("payments.refund", `{"amount":5000}`))
	res := f.decide(t, request("payments.refund", `{"amount":5001}`))
	if res.Verdict != TooManyPending || res.Approval.ID != "" {
		t.Fatalf("verdict %d approval %q, want too many pending and no new approval", res.Verdict, res.Approval.ID)
	}
	entries, _ := f.store.ListAudit(context.Background(), audit.Filter{Limit: 1})
	if e := entries[0]; e.Outcome != audit.OutcomeBlocked || e.Detail != "too many pending approvals" {
		t.Errorf("last entry = %+v", e)
	}
}

// resolverFunc lets a test answer assessments inline.
type resolverFunc func() (consequence.Assessment, error)

func (f resolverFunc) Assess(context.Context, string, map[string]any) (consequence.Assessment, error) {
	return f()
}

// failingAudit makes every audit write fail.
type failingAudit struct{ store.Memory }

func (*failingAudit) AppendAudit(context.Context, audit.Entry) (audit.Entry, error) {
	return audit.Entry{}, errors.New("disk full")
}

func TestErrors(t *testing.T) {
	ctx := context.Background()
	unassessable := resolverFunc(func() (consequence.Assessment, error) { return consequence.Assessment{}, errors.New("map unavailable") })
	nonsense := resolverFunc(func() (consequence.Assessment, error) {
		return consequence.Assessment{Score: 250, Reversibility: consequence.Read, Source: consequence.SourceConfig}, nil
	})

	tests := []struct {
		name    string
		opts    options
		req     Request
		want    string
		wantBad bool
	}{
		{"resolver fails", options{resolver: unassessable}, request("notes.read", `{}`), "consequence could not be assessed", false},
		{"resolver returns nonsense", options{resolver: nonsense}, request("notes.read", `{}`), "consequence could not be assessed", false},
		{"arguments that can't be hashed", options{}, Request{Name: "notes.read", RawArgs: json.RawMessage(`{"a":`)}, "arguments could not be hashed", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newFixture(t, tt.opts).gate.Decide(ctx, tt.req)
			var gerr *Error
			if !errors.As(err, &gerr) || gerr.What != tt.want || gerr.BadArguments != tt.wantBad {
				t.Errorf("err = %#v, want %q (bad arguments %v)", err, tt.want, tt.wantBad)
			}
		})
	}

	t.Run("audit log fails on Admit", func(t *testing.T) {
		f := newFixture(t, options{store: &failingAudit{}})
		err := f.decide(t, request("payments.refund", `{"amount":20}`)).Admit(ctx, "")
		var gerr *Error
		if !errors.As(err, &gerr) || gerr.What != "audit log unavailable" {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("Admit on a denied call", func(t *testing.T) {
		f := newFixture(t, options{})
		if err := f.decide(t, request("db.delete_rows", `{}`)).Admit(ctx, ""); err == nil {
			t.Error("Admit let a denied call through")
		}
	})
}

func TestRecordFillsInTheTime(t *testing.T) {
	f := newFixture(t, options{})
	if err := f.gate.Record(context.Background(), audit.Entry{AgentID: "support-bot", Tool: "x", Outcome: audit.OutcomeRejected}); err != nil {
		t.Fatal(err)
	}
	if e := f.audit(t)[0]; !e.Time.Equal(time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("time = %v", e.Time)
	}
}

func TestSummarize(t *testing.T) {
	if got := Summarize("payments.refund", map[string]any{"note": 1, "amount": 2}); got != "payments.refund with amount, note" {
		t.Errorf("got %q", got)
	}
	if got := Summarize("notes.read", nil); got != "notes.read with no arguments" {
		t.Errorf("got %q", got)
	}
}

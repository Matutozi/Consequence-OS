package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/config"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/receipt"
	"github.com/matutozi/consequence-os/internal/store"
)

const agentKey = "test-agent-key"

// upstream is a fake MCP server that remembers what reached it.
type upstream struct {
	mu   sync.Mutex
	hits []*http.Request
	body []string
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.hits = append(u.hits, r)
	u.body = append(u.body, string(b))
	u.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"from upstream"}],"isError":false}}`)
}

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.hits)
}

func (u *upstream) last() (*http.Request, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits[len(u.hits)-1], u.body[len(u.body)-1]
}

// failingStore makes every audit write fail.
type failingStore struct{ store.Memory }

// Pointer receiver: a value receiver would copy the embedded mutex.
func (*failingStore) AppendAudit(context.Context, audit.Entry) (audit.Entry, error) {
	return audit.Entry{}, errors.New("disk full")
}

type fixture struct {
	proxy       *Proxy
	up          *upstream
	upstreamURL string // the fake upstream's /mcp, for calling it directly
	store       store.Store
	approvals   *approval.Service
	checker     *receipt.Checker // verifies receipts the way the receiver's server would
	clock       *time.Time       // tests move time forward by changing *clock
	approvalLog *syncBuffer      // where the approval service writes approver links
}

// syncBuffer is a bytes.Buffer that is safe to write from several goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
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

// defaultRules is the policy most proxy tests run with.
func defaultRules() []policy.Rule {
	return []policy.Rule{
		{Name: "small-refunds", Tool: "payments.refund", When: policy.Conditions{{Arg: "amount", Op: policy.OpLte, Value: 50}}, Action: policy.ActionAllow},
		{Name: "big-refunds", Tool: "payments.refund", Action: policy.ActionAsk},
		{Name: "no-prod-deletes", Tool: "db.delete*", Action: policy.ActionDeny},
	}
}

// newFixture takes testing.TB, the interface both *testing.T and
// *testing.B satisfy, so benchmarks can use it too.
func newFixture(t testing.TB, st store.Store) fixture {
	t.Helper() // failures point at the caller, not this line
	return newFixtureWithRules(t, st, defaultRules())
}

func newFixtureWithRules(t testing.TB, st store.Store, rules []policy.Rule) fixture {
	t.Helper()
	up := &upstream{}
	srv := httptest.NewServer(up)
	t.Cleanup(srv.Close)

	engine, err := policy.NewEngine(rules, policy.Levels{"notes.read": policy.LevelRead, "payments.refund": policy.LevelIrreversible})
	if err != nil {
		t.Fatal(err)
	}
	if st == nil {
		st = store.NewMemory()
	}
	clock := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	approvalLog := &syncBuffer{}
	svc := approval.NewService(approval.Options{
		Repo: st, Validity: 10 * time.Minute, PublicURL: "http://cos.test",
		Approvers: map[string][]string{"acme": {"ada@acme.example"}},
		Log:       slog.New(slog.NewTextHandler(approvalLog, nil)), Now: now,
	})
	ed, ml, err := receipt.GenerateSeeds()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := receipt.LoadKeys(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := receipt.NewChecker(keys, st, now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Options{
		Upstream:       srv.URL + "/mcp",
		Agents:         []config.Agent{{ID: "support-bot", OwnerID: "acme", APIKey: agentKey}},
		AllowedOrigins: []string{"http://localhost:3000"},
		Engine:         engine,
		Store:          st,
		Approvals:      svc,
		Receipts:       receipt.NewIssuer(keys, "http://cos.test", 5*time.Minute, now),
		Log:            discard,
		Now:            now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{proxy: p, up: up, upstreamURL: srv.URL + "/mcp", store: st, approvals: svc, checker: checker, clock: &clock, approvalLog: approvalLog}
}

func call(tool string, args string) string {
	return `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + args +
		`,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
}

func (f fixture) do(method, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+agentKey)
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	f.proxy.ServeHTTP(rec, req)
	return rec
}

func TestProxy(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		body          string
		headers       map[string]string
		wantStatus    int
		wantForwarded bool
		wantInBody    string // substring of the response
		wantOutcome   audit.Outcome
	}{
		{
			name: "no API key", body: call("notes.read", `{}`), headers: map[string]string{"Authorization": ""},
			wantStatus: 401, wantInBody: "missing or unknown API key",
		},
		{
			name: "unknown API key", body: call("notes.read", `{}`), headers: map[string]string{"Authorization": "Bearer nope"},
			wantStatus: 401, wantInBody: "missing or unknown API key",
		},
		{
			name: "foreign origin", body: call("notes.read", `{}`), headers: map[string]string{"Origin": "https://evil.example"},
			wantStatus: 403, wantInBody: "origin not allowed",
		},
		{
			name: "allowed origin", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, headers: map[string]string{"Origin": "http://localhost:3000"},
			wantStatus: 200, wantForwarded: true,
		},
		{name: "batch rejected", body: `[` + call("notes.read", `{}`) + `]`, wantStatus: 400, wantInBody: "batch"},
		{name: "invalid JSON", body: `{"jsonrpc":`, wantStatus: 400, wantInBody: "parse error"},
		{
			name:       "duplicate argument key rejected",
			body:       call("payments.refund", `{"amount":10,"amount":5000}`),
			wantStatus: 400, wantInBody: "duplicate keys",
		},
		{
			name:       "duplicate tool name rejected",
			body:       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.read","name":"payments.refund"}}`,
			wantStatus: 400, wantInBody: "duplicate keys",
		},
		{
			name:       "case-variant tool name rejected",
			body:       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.read","Name":"db.delete_users"}}`,
			wantStatus: 400, wantInBody: "differ only in letter case",
		},
		{
			name:       "case-variant argument rejected",
			body:       call("payments.refund", `{"amount":10,"Amount":5000}`),
			wantStatus: 400, wantInBody: "differ only in letter case",
		},
		{
			name:       "case-variant key deep inside arguments rejected",
			body:       call("payments.refund", `{"lines":[{"qty":1,"QTY":900}]}`),
			wantStatus: 400, wantInBody: "differ only in letter case",
		},
		{
			name:       "case-variant top-level method rejected",
			body:       `{"jsonrpc":"2.0","id":1,"method":"tools/list","Method":"tools/call"}`,
			wantStatus: 400, wantInBody: "differ only in letter case",
		},
		{
			name: "tools/list passes through", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			wantStatus: 200, wantForwarded: true, wantInBody: "from upstream",
		},
		{
			name: "notification passes through", body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			wantStatus: 200, wantForwarded: true,
		},
		{
			name: "read tool allowed by default", body: call("notes.read", `{"note_id":"welcome"}`),
			wantStatus: 200, wantForwarded: true, wantInBody: "from upstream", wantOutcome: audit.OutcomeForwarded,
		},
		{
			name: "small refund allowed", body: call("payments.refund", `{"charge_id":"ch_1","amount":20}`),
			wantStatus: 200, wantForwarded: true, wantInBody: "from upstream", wantOutcome: audit.OutcomeForwarded,
		},
		{
			name: "big refund held", body: call("payments.refund", `{"charge_id":"ch_1","amount":5000}`),
			wantStatus: 200, wantInBody: "Approval pending", wantOutcome: audit.OutcomeHeld,
		},
		{
			name: "delete denied", body: call("db.delete_users", `{}`),
			wantStatus: 200, wantInBody: `policy rule \"no-prod-deletes\"`, wantOutcome: audit.OutcomeBlocked,
		},
		{
			name: "unknown tool held", body: call("rockets.launch", `{}`),
			wantStatus: 200, wantInBody: "Approval pending", wantOutcome: audit.OutcomeHeld,
		},
		{
			name: "Mcp-Name mismatch", body: call("notes.read", `{}`), headers: map[string]string{headerName: "payments.refund"},
			wantStatus: 400, wantInBody: "Header mismatch", wantOutcome: audit.OutcomeRejected,
		},
		{
			name: "Mcp-Method mismatch", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, headers: map[string]string{headerMethod: "tools/call"},
			wantStatus: 400, wantInBody: "Header mismatch",
		},
		{
			name: "matching headers accepted", body: call("notes.read", `{}`),
			headers:    map[string]string{headerMethod: "tools/call", headerName: "notes.read"},
			wantStatus: 200, wantForwarded: true, wantOutcome: audit.OutcomeForwarded,
		},
		{
			name: "tools/call as notification rejected", body: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"payments.refund"}}`,
			wantStatus: 400, wantInBody: "needs an id", wantOutcome: audit.OutcomeRejected,
		},
		{
			name: "arguments must be an object", body: call("payments.refund", `[5000]`),
			wantStatus: 400, wantInBody: "must be an object", wantOutcome: audit.OutcomeRejected,
		},
		{
			name: "missing tool name", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`,
			wantStatus: 400, wantInBody: "params.name", wantOutcome: audit.OutcomeRejected,
		},
		{name: "GET passes through", method: http.MethodGet, wantStatus: 200, wantForwarded: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, nil)
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			rec := f.do(method, tt.body, tt.headers)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.wantStatus, rec.Body)
			}
			if got := f.up.count() > 0; got != tt.wantForwarded {
				t.Errorf("forwarded = %v, want %v", got, tt.wantForwarded)
			}
			if !strings.Contains(rec.Body.String(), tt.wantInBody) {
				t.Errorf("body %s does not contain %q", rec.Body, tt.wantInBody)
			}

			entries, _ := f.store.ListAudit(context.Background(), audit.Filter{})
			if tt.wantOutcome == "" {
				if len(entries) != 0 {
					t.Errorf("expected no audit entry, got %+v", entries)
				}
				return
			}
			if len(entries) != 1 {
				t.Fatalf("got %d audit entries, want 1", len(entries))
			}
			if entries[0].Outcome != tt.wantOutcome {
				t.Errorf("outcome = %q, want %q", entries[0].Outcome, tt.wantOutcome)
			}
		})
	}
}

func TestForwardedRequestIsUntouched(t *testing.T) {
	f := newFixture(t, nil)
	body := call("payments.refund", `{ "amount" : 20, "charge_id":"ch_1" }`) // odd spacing must survive
	rec := f.do(http.MethodPost, body, map[string]string{
		headerReceipt:         "forged-by-agent",
		headerProtocolVersion: "2026-07-28",
		"Mcp-Session-Id":      "legacy-session",
	})
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}

	req, got := f.up.last()
	checks := []struct {
		name      string
		got, want string
	}{
		{"body unchanged apart from the receipt", withoutReceipt(t, got), withoutReceipt(t, body)},
		{"upstream path", req.URL.Path, "/mcp"},
		{"agent key not forwarded", req.Header.Get("Authorization"), ""},
		{"agent-supplied receipt replaced", fmt.Sprint(strings.Contains(req.Header.Get(headerReceipt), "forged-by-agent")), "false"},
		{"protocol header kept", req.Header.Get(headerProtocolVersion), "2026-07-28"},
		{"session header kept", req.Header.Get("Mcp-Session-Id"), "legacy-session"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestAuditEntryContents(t *testing.T) {
	f := newFixture(t, nil)
	f.do(http.MethodPost, call("payments.refund", `{"charge_id":"ch_secret_123","amount":5000}`), nil)

	entries, _ := f.store.ListAudit(context.Background(), audit.Filter{})
	if len(entries) != 1 {
		t.Fatalf("got %d entries", len(entries))
	}
	e := entries[0]
	want := audit.Entry{
		ID: e.ID, Time: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC),
		AgentID: "support-bot", OwnerID: "acme", Tool: "payments.refund",
		ParamsHash: e.ParamsHash, Summary: "payments.refund with amount, charge_id",
		Level: policy.LevelIrreversible, Decision: policy.ActionAsk, Rule: "big-refunds", Outcome: audit.OutcomeHeld,
		ApprovalID: e.ApprovalID,
		Seq:        1, PrevHash: "", Hash: e.Hash, // the first entry in the chain
	}
	if e != want {
		t.Errorf("entry = %+v\nwant    %+v", e, want)
	}
	if !strings.HasPrefix(e.ApprovalID, "apr_") {
		t.Errorf("approval id = %q", e.ApprovalID)
	}
	if !strings.HasPrefix(e.ParamsHash, "sha256:") {
		t.Errorf("params hash = %q", e.ParamsHash)
	}
	raw, _ := json.Marshal(e)
	if strings.Contains(string(raw), "ch_secret_123") || strings.Contains(string(raw), "5000") {
		t.Errorf("audit entry leaks argument values: %s", raw)
	}
}

func TestHeldResultShape(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.do(http.MethodPost, call("payments.refund", `{"amount":5000}`), nil)

	var resp struct {
		ID     int `json:"id"`
		Result struct {
			IsError    bool   `json:"isError"`
			ResultType string `json:"resultType"`
			Content    []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != 7 || !resp.Result.IsError || resp.Result.ResultType != "complete" ||
		len(resp.Result.Content) != 1 || resp.Result.Content[0].Type != "text" {
		t.Errorf("unexpected result: %+v", resp)
	}

	// A legacy client (no per-request _meta) gets no resultType.
	legacy := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"payments.refund","arguments":{"amount":5000}}}`
	rec = f.do(http.MethodPost, legacy, nil)
	if strings.Contains(rec.Body.String(), "resultType") {
		t.Errorf("legacy result should not carry resultType: %s", rec.Body)
	}
}

func TestFailsClosedWhenAuditFails(t *testing.T) {
	f := newFixture(t, &failingStore{})
	rec := f.do(http.MethodPost, call("notes.read", `{}`), nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if f.up.count() != 0 {
		t.Error("call was forwarded even though the audit write failed")
	}
}

func TestUpstreamDown(t *testing.T) {
	engine, _ := policy.NewEngine(nil, policy.Levels{"notes.read": policy.LevelRead})
	st := store.NewMemory()
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := New(Options{
		Upstream:  "http://127.0.0.1:1/mcp", // nothing listens on port 1
		Agents:    []config.Agent{{ID: "a", OwnerID: "o", APIKey: agentKey}},
		Engine:    engine,
		Store:     st,
		Approvals: approval.NewService(approval.Options{Repo: st, Validity: time.Minute, Log: discard}),
		Receipts:  testIssuer(t),
		Log:       discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(call("notes.read", `{}`)))
	req.Header.Set("Authorization", "Bearer "+agentKey)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "upstream MCP server unavailable") {
		t.Errorf("got %d %s", rec.Code, rec.Body)
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	if _, err := New(Options{Upstream: "not a url"}); err == nil {
		t.Error("expected an error for a bad upstream URL")
	}
	if _, err := New(Options{Upstream: "http://x/mcp"}); err == nil {
		t.Error("expected an error when required options are missing")
	}
}

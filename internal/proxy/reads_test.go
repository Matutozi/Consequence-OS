package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
)

func readResource(uri string) string {
	b, _ := json.Marshal(uri)
	return `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":` + string(b) + `}}`
}

func getPrompt(name, args string) string {
	return `{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"` + name + `","arguments":` + args + `}}`
}

func readRules() []policy.Rule {
	return []policy.Rule{
		{Name: "no-system-files", Tool: "resource:file:///etc/*", Action: policy.ActionDeny},
		{Name: "incident-prompts-need-review", Tool: "prompt:incident-*", Action: policy.ActionAsk},
		{Name: "no-customer-exports", Tool: "prompt:export", When: policy.Conditions{{Arg: "table", Op: policy.OpEq, Value: "customers", Fold: true}}, Action: policy.ActionDeny},
	}
}

func TestReads(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		headers       map[string]string
		wantStatus    int
		wantForwarded bool
		wantInBody    string
		wantOutcome   audit.Outcome // "" means no audit entry
		wantTool      string
	}{
		{
			name: "unlisted resource is allowed and audited", body: readResource("file:///notes/welcome.md"),
			wantStatus: 200, wantForwarded: true, wantInBody: "from upstream",
			wantOutcome: audit.OutcomeForwarded, wantTool: "resource:file:///notes/welcome.md",
		},
		{
			name: "deny rule on a resource blocks it", body: readResource("file:///etc/passwd"),
			wantStatus: 200, wantInBody: `Blocked by ConsequenceOS: policy rule \"no-system-files\" does not allow reading file:///etc/passwd`,
			wantOutcome: audit.OutcomeBlocked, wantTool: "resource:file:///etc/passwd",
		},
		{
			name: "the glob reaches nested paths", body: readResource("file:///etc/ssl/private/key.pem"),
			wantStatus: 200, wantInBody: `"code":-32030`, wantOutcome: audit.OutcomeBlocked,
		},
		{
			name: "dot segments are refused", body: readResource("file:///tmp/../etc/passwd"),
			wantStatus: 400, wantInBody: ". or .. path segments", wantOutcome: audit.OutcomeRejected,
		},
		{
			name: "encoded letters are refused", body: readResource("file:///%65tc/passwd"),
			wantStatus: 400, wantInBody: "not percent-encoded", wantOutcome: audit.OutcomeRejected,
		},
		{
			name: "upper-case scheme is refused", body: readResource("FILE:///etc/passwd"),
			wantStatus: 400, wantInBody: "lower case", wantOutcome: audit.OutcomeRejected,
		},
		{
			name: "resource read without a uri", body: `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{}}`,
			wantStatus: 400, wantInBody: "needs params.uri", wantOutcome: audit.OutcomeRejected,
		},
		{
			name: "resource read sent as a notification", body: `{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///notes/a"}}`,
			wantStatus: 400, wantInBody: "resources/read needs an id", wantOutcome: audit.OutcomeRejected,
		},
		{
			name: "Mcp-Name must match the URI", body: readResource("file:///etc/passwd"),
			headers:    map[string]string{headerMethod: "resources/read", headerName: "file:///notes/welcome.md"},
			wantStatus: 400, wantInBody: "Header mismatch: Mcp-Name", wantOutcome: audit.OutcomeRejected,
		},
		{
			name: "Mcp-Name that matches is fine", body: readResource("file:///notes/welcome.md"),
			headers:    map[string]string{headerMethod: "resources/read", headerName: "file:///notes/welcome.md"},
			wantStatus: 200, wantForwarded: true, wantOutcome: audit.OutcomeForwarded,
		},
		{
			name: "Mcp-Method must match the body", body: readResource("file:///etc/passwd"),
			headers:    map[string]string{headerMethod: "tools/list"},
			wantStatus: 400, wantInBody: "Header mismatch: Mcp-Method", wantOutcome: audit.OutcomeRejected,
		},
		{
			name: "unlisted prompt is allowed", body: getPrompt("summarize", `{"style":"short"}`),
			wantStatus: 200, wantForwarded: true, wantOutcome: audit.OutcomeForwarded, wantTool: "prompt:summarize",
		},
		{
			name: "conditions work on prompt arguments", body: getPrompt("export", `{"table":"Customers"}`),
			wantStatus: 200, wantInBody: "does not allow getting the prompt export", wantOutcome: audit.OutcomeBlocked,
		},
		{
			name: "an ask rule holds a prompt", body: getPrompt("incident-report", `{}`),
			wantStatus: 200, wantInBody: "Approval pending: getting the prompt incident-report needs a human", wantOutcome: audit.OutcomeHeld,
		},
		{
			name: "prompt arguments must be an object", body: getPrompt("summarize", `["x"]`),
			wantStatus: 400, wantInBody: "prompts/get arguments must be an object", wantOutcome: audit.OutcomeRejected,
		},
		{
			name: "a tool can't pose as a resource", body: call("resource:file:///notes/a", `{}`),
			wantStatus: 400, wantInBody: "may not start with resource: or prompt:", wantOutcome: audit.OutcomeRejected,
		},
		{
			name: "control characters in a tool name are refused", body: call(`notes.read\u0000x`, `{}`),
			wantStatus: 400, wantInBody: "control characters", wantOutcome: audit.OutcomeRejected,
		},
		{
			name: "resource listing still passes through", body: `{"jsonrpc":"2.0","id":5,"method":"resources/list"}`,
			wantStatus: 200, wantForwarded: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixtureWithRules(t, nil, readRules())
			rec := f.do(http.MethodPost, tt.body, tt.headers)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body %s", rec.Code, tt.wantStatus, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), tt.wantInBody) {
				t.Errorf("body %s does not contain %q", rec.Body, tt.wantInBody)
			}
			if forwarded := f.up.count() > 0; forwarded != tt.wantForwarded {
				t.Errorf("forwarded = %v, want %v", forwarded, tt.wantForwarded)
			}
			entries, _ := f.store.ListAudit(context.Background(), audit.Filter{})
			switch {
			case tt.wantOutcome == "" && len(entries) > 0:
				t.Errorf("got audit entry %+v, want none", entries[0])
			case tt.wantOutcome != "" && len(entries) != 1:
				t.Fatalf("got %d audit entries, want 1", len(entries))
			case tt.wantOutcome != "":
				e := entries[0]
				if e.Outcome != tt.wantOutcome {
					t.Errorf("outcome = %s (%s), want %s", e.Outcome, e.Detail, tt.wantOutcome)
				}
				if tt.wantTool != "" && e.Tool != tt.wantTool {
					t.Errorf("audit tool = %q, want %q", e.Tool, tt.wantTool)
				}
				if e.Outcome == audit.OutcomeForwarded && (e.Level != policy.LevelRead || e.ReceiptID != "") {
					t.Errorf("forwarded read: level %s, receipt %q; want read and none", e.Level, e.ReceiptID)
				}
			}
		})
	}
}

func TestReadsCarryNoReceipt(t *testing.T) {
	f := newFixtureWithRules(t, nil, readRules())
	body := `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///notes/a","_meta":{"consequenceReceipt":"forged"}}}`
	headers := map[string]string{headerReceipt: "forged"}
	if rec := f.do(http.MethodPost, body, headers); rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	got, sent := f.up.last()
	if got.Header.Get(headerReceipt) != "" {
		t.Errorf("upstream got a receipt header %q on a read", got.Header.Get(headerReceipt))
	}
	if sent != body {
		t.Errorf("read body changed on the way: %s", sent)
	}
}

func TestApprovedReadGoesThroughOnce(t *testing.T) {
	f := newFixtureWithRules(t, nil, readRules())
	prompt := getPrompt("incident-report", `{"id":"inc_7"}`)

	held := f.do(http.MethodPost, prompt, nil).Body.String()
	approveDirectly(t, f, approvalID(t, held), true)

	if body := f.do(http.MethodPost, prompt, nil).Body.String(); !strings.Contains(body, "from upstream") {
		t.Fatalf("approved retry: %s", body)
	}
	if _, sent := f.up.last(); strings.Contains(sent, "consequenceReceipt") {
		t.Errorf("approved read carried a receipt: %s", sent)
	}
	if body := f.do(http.MethodPost, prompt, nil).Body.String(); !strings.Contains(body, "Approval pending") {
		t.Errorf("second retry should need a new approval: %s", body)
	}
	if f.up.count() != 1 {
		t.Errorf("forwarded %d times, want 1", f.up.count())
	}
}

func TestLimitsApplyToReads(t *testing.T) {
	rules := []policy.Rule{{Name: "read-burst", Tool: "resource:*", Limit: &policy.Limit{Max: 2, Per: time.Hour}, Action: policy.ActionDeny}}
	f := newFixtureWithRules(t, nil, rules)
	for i, uri := range []string{"file:///a", "https://docs.acme.example/b", "file:///c"} {
		body := f.do(http.MethodPost, readResource(uri), nil).Body.String()
		blocked := strings.Contains(body, "read-burst")
		if want := i == 2; blocked != want {
			t.Errorf("read %d blocked = %v, want %v: %s", i+1, blocked, want, body)
		}
	}
}

func TestCheckResourceURI(t *testing.T) {
	tests := []struct {
		uri  string
		want string // "" means accepted; otherwise part of the reason
	}{
		{"file:///notes/welcome.md", ""},
		{"https://docs.acme.example/a/b?x=1#top", ""},
		{"postgres://db.acme.example/customers/42", ""},
		{"ui://widget/chart", ""},
		{"urn:isbn:0451450523", ""},
		{"file:///notes/%2F", ""},                     // encoded reserved characters keep their meaning
		{"https://Ada@docs.acme.example/x", ""},       // user info may keep its case
		{"https://docs.acme.example/a.b/..c/.d", ""},  // dots inside a segment are fine
		{"https://docs.acme.example/a?next=../b", ""}, // the query isn't a path
		{"file:///tmp/../etc/passwd", ". or .."},
		{"file:///./etc/passwd", ". or .."},
		{"file:///etc/..", ". or .."},
		{"file:///%2e%2e/etc", "percent-encoded"},
		{"file:///%65tc/passwd", "percent-encoded"},
		{"file:///etc/%zz", "two hex digits"},
		{"file:///etc/%2", "two hex digits"},
		{"FILE:///etc/passwd", "scheme in lower case"},
		{"https://DOCS.acme.example/x", "host in lower case"},
		{"/etc/passwd", "needs a scheme"},
		{":nothing", "needs a scheme"},
		{"1http://x", "needs a scheme"},
		{"file:///etc/pass wd", "spaces"},
		{"file:///etc/passwd\n", "control characters"},
		{`file:///C:\Windows\..\x`, "backslashes"},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			got := checkResourceURI(tt.uri)
			if tt.want == "" && got != "" {
				t.Errorf("refused: %s", got)
			}
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Errorf("got %q, want it to mention %q", got, tt.want)
			}
		})
	}
}

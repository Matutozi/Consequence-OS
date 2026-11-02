package verify

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeVerifier accepts the receipt "good" for any call and records what it saw.
type fakeVerifier struct {
	tool string
	args string
}

func (f *fakeVerifier) Verify(_ context.Context, receipt []byte, tool string, arguments []byte) (*Receipt, error) {
	f.tool, f.args = tool, string(arguments)
	if strings.Trim(string(receipt), `"`) != "good" {
		return nil, ErrBadSignature
	}
	return &Receipt{ReceiptID: "rcpt_1", Action: Action{Tool: tool}}, nil
}

func TestMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		body       string
		header     string
		wantStatus int
		wantReason string
		wantTool   string
		wantArgs   string
	}{
		{name: "non-call passes", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, wantStatus: 200},
		{name: "GET passes", method: http.MethodGet, wantStatus: 200},
		{name: "invalid JSON passes to the server", body: `{nope`, wantStatus: 200},
		{
			name: "call without receipt refused", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payments.refund","arguments":{"amount":5}}}`,
			wantStatus: 403, wantReason: "missing",
		},
		{
			name: "call with bad receipt refused", header: "forged",
			body:       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payments.refund","arguments":{"amount":5}}}`,
			wantStatus: 403, wantReason: "bad_signature",
		},
		{
			name: "receipt in header accepted", header: "good",
			body:       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payments.refund","arguments":{"amount":5}}}`,
			wantStatus: 200, wantTool: "payments.refund", wantArgs: `{"amount":5}`,
		},
		{
			name:       "receipt in _meta accepted",
			body:       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.read","arguments":{},"_meta":{"consequenceReceipt":"good"}}}`,
			wantStatus: 200, wantTool: "notes.read", wantArgs: `{}`,
		},
		{
			name: "case-variant arguments refused even with a receipt", header: "good",
			body:       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payments.refund","arguments":{"amount":5,"Amount":5000}}}`,
			wantStatus: 403, wantReason: "malformed",
		},
		{
			name: "case-variant tool name refused", header: "good",
			body:       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.read","Name":"payments.refund"}}`,
			wantStatus: 403, wantReason: "malformed",
		},
		{
			name: "duplicate keys refused", header: "good",
			body:       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.read","name":"payments.refund"}}`,
			wantStatus: 403, wantReason: "malformed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv := &fakeVerifier{}
			var sawReceipt bool
			var sawBody string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, sawReceipt = FromContext(r.Context())
				b, _ := io.ReadAll(r.Body)
				sawBody = string(b)
			})
			h := Middleware(fv, slog.New(slog.NewTextHandler(io.Discard, nil)))(next)

			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			req := httptest.NewRequest(method, "/mcp", strings.NewReader(tt.body))
			if tt.header != "" {
				req.Header.Set(HeaderName, tt.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantReason != "" && !strings.Contains(rec.Body.String(), `"reason":"`+tt.wantReason+`"`) {
				t.Errorf("body %s lacks reason %s", rec.Body, tt.wantReason)
			}
			if tt.wantTool != "" {
				if fv.tool != tt.wantTool || fv.args != tt.wantArgs {
					t.Errorf("verifier saw tool %q args %q", fv.tool, fv.args)
				}
				if !sawReceipt {
					t.Error("verified receipt not in request context")
				}
			}
			if rec.Code == 200 && sawBody != tt.body {
				t.Errorf("handler got body %q, want the original", sawBody)
			}
		})
	}
}

func TestReasonRoundTrip(t *testing.T) {
	for sentinel, code := range reasons {
		if got := ErrorForReason(code); got != sentinel {
			t.Errorf("ErrorForReason(%q) = %v, want %v", code, got, sentinel)
		}
		if got := Reason(sentinel); got != code {
			t.Errorf("Reason(%v) = %q, want %q", sentinel, got, code)
		}
	}
}

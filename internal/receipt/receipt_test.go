package receipt

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

	"github.com/matutozi/consequence-os/pkg/verify"
)

// usedMemory is a minimal UsedStore for these tests.
type usedMemory struct {
	mu   sync.Mutex
	used map[string]bool
}

func (u *usedMemory) MarkReceiptUsed(_ context.Context, id string, _, _ time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.used[id] {
		return verify.ErrAlreadyUsed
	}
	u.used[id] = true
	return nil
}

var testStart = time.Date(2026, 11, 2, 10, 14, 0, 0, time.UTC)

type harness struct {
	seeds   [2]string // the seeds keys came from
	keys    *Keys
	issuer  *Issuer
	checker *Checker
	clock   *time.Time
}

func newHarness(t *testing.T) harness {
	t.Helper()
	ed, ml, err := GenerateSeeds()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := LoadKeys(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	clock := testStart
	now := func() time.Time { return clock }
	checker, err := NewChecker(keys, &usedMemory{used: map[string]bool{}}, now)
	if err != nil {
		t.Fatal(err)
	}
	return harness{seeds: [2]string{ed, ml}, keys: keys, issuer: NewIssuer(keys, "http://cos.test", 5*time.Minute, now), checker: checker, clock: &clock}
}

const args = `{"amount":4800,"po":"00231"}`

func (h harness) issue(t *testing.T, approvedBy string) []byte {
	t.Helper()
	hash, _ := verify.ParamsHash([]byte(args))
	encoded, _, err := h.issuer.Issue(Input{
		AgentID: "procurement-bot", OwnerID: "acme", ApprovedBy: approvedBy,
		Tool: "purchase_order.confirm", ParamsHash: hash, Summary: "purchase_order.confirm with amount, po",
		Level: "irreversible", Policy: "po-over-500-needs-manager",
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestIssuedReceiptContents(t *testing.T) {
	h := newHarness(t)
	r, err := h.checker.Verify(context.Background(), "payments-api", h.issue(t, "ada@acme.example"), "purchase_order.confirm", []byte(args))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	checks := []struct {
		name      string
		got, want any
	}{
		{"type", r.Type, verify.ReceiptType},
		{"id prefix", strings.HasPrefix(r.ReceiptID, "rcpt_"), true},
		{"issuer", r.Issuer, "http://cos.test"},
		{"decision", r.Decision, verify.DecisionHumanApproved},
		{"approved by", r.ApprovedBy, "ada@acme.example"},
		{"policy", r.Policy, "po-over-500-needs-manager"},
		{"issued", r.IssuedAt.Time, testStart},
		{"expires", r.ExpiresAt.Time, testStart.Add(5 * time.Minute)},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}

	policyOnly, err := h.checker.Verify(context.Background(), "payments-api", h.issue(t, ""), "purchase_order.confirm", []byte(args))
	if err != nil {
		t.Fatal(err)
	}
	if policyOnly.Decision != verify.DecisionPolicyAllowed || policyOnly.ApprovedBy != "" {
		t.Errorf("policy receipt: decision %q approved_by %q", policyOnly.Decision, policyOnly.ApprovedBy)
	}
}

func TestEncodingFollowsTheDraftShape(t *testing.T) {
	h := newHarness(t)
	var signed map[string]json.RawMessage
	if err := json.Unmarshal(h.issue(t, ""), &signed); err != nil {
		t.Fatal(err)
	}
	if len(signed) != 2 || signed["payload"] == nil || signed["signatures"] == nil {
		t.Fatalf("top level must be exactly payload and signatures, got %v", signed)
	}
	var sigs []verify.Signature
	_ = json.Unmarshal(signed["signatures"], &sigs)
	for i, alg := range []string{verify.AlgEd25519, verify.AlgMLDSA87} {
		raw, _ := b64.DecodeString(sigs[i].Protected)
		want := `{"typ":"vnd.consequenceos.receipt.v0+json","alg":"` + alg + `","kid":"`
		if !strings.HasPrefix(string(raw), want) {
			t.Errorf("signature %d header = %s", i, raw)
		}
	}
	var payloadB64 string
	_ = json.Unmarshal(signed["payload"], &payloadB64)
	payload, _ := b64.DecodeString(payloadB64)
	canonical, _ := verify.Canonicalize(payload)
	if !bytes.Equal(payload, canonical) {
		t.Errorf("payload is not canonical: %s", payload)
	}
	if !strings.Contains(string(payload), `"issued_at":"2026-11-02T10:14:00Z"`) {
		t.Errorf("times must be whole-second UTC: %s", payload)
	}
}

// mutate decodes a receipt, lets f change it, and re-encodes it.
func mutate(t *testing.T, encoded []byte, f func(*verify.Signed)) []byte {
	t.Helper()
	var s verify.Signed
	if err := json.Unmarshal(encoded, &s); err != nil {
		t.Fatal(err)
	}
	f(&s)
	out, _ := json.Marshal(s)
	return out
}

func TestVerifyRejects(t *testing.T) {
	tests := []struct {
		name    string
		receipt func(t *testing.T, h harness) []byte
		tool    string
		args    string
		advance time.Duration
		want    error
	}{
		{
			name:    "valid",
			receipt: func(t *testing.T, h harness) []byte { return h.issue(t, "") },
			want:    nil,
		},
		{
			name:    "amount changed after approval",
			receipt: func(t *testing.T, h harness) []byte { return h.issue(t, "") },
			args:    `{"amount":48000,"po":"00231"}`,
			want:    verify.ErrParamsMismatch,
		},
		{
			name:    "different tool",
			receipt: func(t *testing.T, h harness) []byte { return h.issue(t, "") },
			tool:    "purchase_order.cancel",
			want:    verify.ErrToolMismatch,
		},
		{
			name:    "expired",
			receipt: func(t *testing.T, h harness) []byte { return h.issue(t, "") },
			advance: 5 * time.Minute,
			want:    verify.ErrExpired,
		},
		{
			name: "payload edited",
			receipt: func(t *testing.T, h harness) []byte {
				return mutate(t, h.issue(t, ""), func(s *verify.Signed) {
					p, _ := b64.DecodeString(s.Payload)
					p = bytes.Replace(p, []byte(`"decision":"policy_allowed"`), []byte(`"decision":"human_approved"`), 1)
					s.Payload = b64.EncodeToString(p)
				})
			},
			want: verify.ErrBadSignature,
		},
		{
			name: "post-quantum signature stripped",
			receipt: func(t *testing.T, h harness) []byte {
				return mutate(t, h.issue(t, ""), func(s *verify.Signed) { s.Signatures = s.Signatures[:1] })
			},
			want: verify.ErrMalformed,
		},
		{
			name: "signatures swapped",
			receipt: func(t *testing.T, h harness) []byte {
				return mutate(t, h.issue(t, ""), func(s *verify.Signed) {
					s.Signatures[0], s.Signatures[1] = s.Signatures[1], s.Signatures[0]
				})
			},
			want: verify.ErrMalformed,
		},
		{
			name: "signed by someone else's keys",
			receipt: func(t *testing.T, h harness) []byte {
				return newHarness(t).issue(t, "") // another server's keys
			},
			want: verify.ErrUnknownKey,
		},
		{
			name:    "not JSON",
			receipt: func(*testing.T, harness) []byte { return []byte("eyJhbGciOi.not.a.receipt") },
			want:    verify.ErrMalformed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			receipt := tt.receipt(t, h)
			*h.clock = h.clock.Add(tt.advance)
			tool, a := "purchase_order.confirm", args
			if tt.tool != "" {
				tool = tt.tool
			}
			if tt.args != "" {
				a = tt.args
			}
			_, err := h.checker.Verify(context.Background(), "payments-api", receipt, tool, []byte(a))
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestSingleUse(t *testing.T) {
	h := newHarness(t)
	receipt := h.issue(t, "")
	if _, err := h.checker.Verify(context.Background(), "payments-api", receipt, "purchase_order.confirm", []byte(args)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.checker.Verify(context.Background(), "payments-api", receipt, "purchase_order.confirm", []byte(args)); !errors.Is(err, verify.ErrAlreadyUsed) {
		t.Errorf("replay: err = %v, want ErrAlreadyUsed", err)
	}
}

func TestFailedCheckDoesNotBurnReceipt(t *testing.T) {
	h := newHarness(t)
	receipt := h.issue(t, "")
	_, _ = h.checker.Verify(context.Background(), "payments-api", receipt, "purchase_order.confirm", []byte(`{"amount":1}`))
	if _, err := h.checker.Verify(context.Background(), "payments-api", receipt, "purchase_order.confirm", []byte(args)); err != nil {
		t.Errorf("a mismatched attempt used up the receipt: %v", err)
	}
}

func TestLoadKeysRejectsBadSeeds(t *testing.T) {
	ed, ml, _ := GenerateSeeds()
	tests := []struct{ name, ed, ml string }{
		{"short ed25519", "abc", ml},
		{"padded ed25519", ed + "=", ml},
		{"short ml-dsa", ed, "abc"},
	}
	for _, tt := range tests {
		if _, err := LoadKeys(tt.ed, tt.ml); err == nil {
			t.Errorf("%s: expected an error", tt.name)
		}
	}
}

func TestHandlers(t *testing.T) {
	h := newHarness(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mux := http.NewServeMux()
	mux.Handle("POST /v1/receipts/verify", VerifyHandler(h.checker, map[string]string{"recv-key": "payments-api"}, log))
	mux.Handle("GET /.well-known/consequence-keys", KeysHandler(h.keys))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// A receiver fetches the keys and checks a receipt offline.
	keys, err := verify.FetchKeys(context.Background(), nil, srv.URL)
	if err != nil {
		t.Fatalf("FetchKeys: %v", err)
	}
	receipt := h.issue(t, "")
	offline := &verify.Offline{Keys: keys, Now: func() time.Time { return *h.clock }}
	if _, err := offline.Verify(context.Background(), receipt, "purchase_order.confirm", []byte(args)); err != nil {
		t.Fatalf("offline verify: %v", err)
	}

	// Without the receiver's key the server refuses, and the receipt isn't used up.
	for _, key := range []string{"", "wrong-key"} {
		if _, err := verify.NewClient(srv.URL, key).Verify(context.Background(), receipt, "purchase_order.confirm", []byte(args)); !errors.Is(err, verify.ErrUnauthorized) {
			t.Errorf("key %q: err = %v, want ErrUnauthorized", key, err)
		}
	}

	// Then online, with single use. One call per check.
	client := verify.NewClient(srv.URL, "recv-key")
	if _, err := client.Verify(context.Background(), receipt, "purchase_order.confirm", []byte(args)); err != nil {
		t.Fatalf("online verify: %v", err)
	}
	if _, err := client.Verify(context.Background(), receipt, "purchase_order.confirm", []byte(args)); !errors.Is(err, verify.ErrAlreadyUsed) {
		t.Errorf("online replay: err = %v, want ErrAlreadyUsed", err)
	}

	// A receipt sent as a JSON string works too.
	asString, _ := json.Marshal(string(h.issue(t, "")))
	if _, err := client.Verify(context.Background(), asString, "purchase_order.confirm", []byte(args)); err != nil {
		t.Errorf("receipt as string: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/receipts/verify", strings.NewReader(`{"tool":""}`))
	req.Header.Set("Authorization", "Bearer recv-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed request: status %d, want 400", resp.StatusCode)
	}
}

// TestPayloadFitsDraftContentRules guards the IETF draft's content rules:
// only objects, arrays, strings and non-negative integers, nested at most
// 8 levels. No booleans, null or fractions.
func TestPayloadFitsDraftContentRules(t *testing.T) {
	h := newHarness(t)
	for _, approvedBy := range []string{"", "ada@acme.example"} {
		var signed verify.Signed
		if err := json.Unmarshal(h.issue(t, approvedBy), &signed); err != nil {
			t.Fatal(err)
		}
		payload, err := b64.DecodeString(signed.Payload)
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(bytes.NewReader(payload))
		dec.UseNumber() // keep numbers as written, to spot fractions
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		if problem := draftContentProblem(v, 1); problem != "" {
			t.Errorf("approved_by %q: %s", approvedBy, problem)
		}
	}
}

func draftContentProblem(v any, depth int) string {
	if depth > 8 {
		return "nested deeper than 8 levels"
	}
	switch x := v.(type) {
	case string:
		return ""
	case json.Number:
		if n, err := x.Int64(); err != nil || n < 0 {
			return "number " + x.String() + " is not a non-negative integer"
		}
		return ""
	case map[string]any:
		for k, child := range x {
			if p := draftContentProblem(child, depth+1); p != "" {
				return k + ": " + p
			}
		}
		return ""
	case []any:
		for _, child := range x {
			if p := draftContentProblem(child, depth+1); p != "" {
				return p
			}
		}
		return ""
	}
	return "value of type " + strings.TrimPrefix(fmt.Sprintf("%T", v), "*") + " is not allowed"
}

func TestAuditHeadSigning(t *testing.T) {
	h := newHarness(t)
	jwks, _ := json.Marshal(h.keys.JWKS())
	keys, err := verify.ParseJWKS(jwks) // what an auditor gets from /.well-known/consequence-keys
	if err != nil {
		t.Fatal(err)
	}
	signed, err := h.keys.SignAuditHead("http://cos.test", 42, "sha256:"+strings.Repeat("ab", 32), testStart)
	if err != nil {
		t.Fatal(err)
	}

	head, err := verify.VerifyAuditHead(signed, keys)
	if err != nil {
		t.Fatalf("VerifyAuditHead: %v", err)
	}
	if head.Seq != 42 || head.Issuer != "http://cos.test" || !head.SignedAt.Equal(testStart) {
		t.Errorf("head = %+v", head)
	}

	// A head is not a receipt, and a receipt is not a head.
	if _, err := verify.VerifyOffline(signed, keys, testStart); !errors.Is(err, verify.ErrMalformed) {
		t.Errorf("head accepted as a receipt: %v", err)
	}
	if _, err := verify.VerifyAuditHead(h.issue(t, ""), keys); !errors.Is(err, verify.ErrMalformed) {
		t.Errorf("receipt accepted as a head: %v", err)
	}

	// A changed payload fails the signatures.
	var s verify.Signed
	_ = json.Unmarshal(signed, &s)
	forged, _ := json.Marshal(verify.AuditHead{Type: verify.AuditHeadType, Issuer: "http://cos.test", Seq: 41,
		Hash: head.Hash, SignedAt: head.SignedAt})
	canonical, _ := verify.Canonicalize(forged)
	s.Payload = b64.EncodeToString(canonical)
	tampered, _ := json.Marshal(s)
	if _, err := verify.VerifyAuditHead(tampered, keys); !errors.Is(err, verify.ErrBadSignature) {
		t.Errorf("forged head: err = %v, want ErrBadSignature", err)
	}

	// The head fits the IETF draft's content rules too.
	payload, _ := b64.DecodeString(s.Payload)
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var v any
	_ = dec.Decode(&v)
	if problem := draftContentProblem(v, 1); problem != "" {
		t.Error(problem)
	}
}

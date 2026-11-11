package receipt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/pkg/verify"
)

var configConsequence = verify.Consequence{Score: 80, Reversibility: verify.ReversibilityNone, Source: verify.SourceConfig}

// issueV1 issues a v1 receipt for audience.
func (h harness) issueV1(t *testing.T, audience string) []byte {
	t.Helper()
	hash, _ := verify.ParamsHash([]byte(args))
	c := configConsequence
	encoded, _, err := h.issuer.Issue(Input{
		AgentID: "procurement-bot", OwnerID: "acme", Tool: "purchase_order.confirm", ParamsHash: hash,
		Summary: "purchase_order.confirm with amount, po", Level: "irreversible", Policy: "po-small",
		Audience: audience, Consequence: &c,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// signPayload signs any payload under typ with h's keys, to build receipts
// the issuer itself would never make.
func (h harness) signPayload(t *testing.T, payload map[string]any, typ string) []byte {
	t.Helper()
	encoded, err := h.keys.signJSON(payload, typ)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// payloadOf decodes a receipt's payload into a map, for editing and re-signing.
func payloadOf(t *testing.T, encoded []byte) map[string]any {
	t.Helper()
	var s verify.Signed
	if err := json.Unmarshal(encoded, &s); err != nil {
		t.Fatal(err)
	}
	raw, _ := b64.DecodeString(s.Payload)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep numbers as written, so the content rules can be checked
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIssueV1(t *testing.T) {
	h := newHarness(t)
	encoded := h.issueV1(t, "payments-api")
	r, err := h.checker.Verify(context.Background(), "payments-api", encoded, "purchase_order.confirm", []byte(args))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if r.Type != verify.ReceiptTypeV1 || r.Audience != "payments-api" || r.Consequence == nil || *r.Consequence != configConsequence {
		t.Errorf("got type %q, audience %q, consequence %+v", r.Type, r.Audience, r.Consequence)
	}

	var s verify.Signed
	_ = json.Unmarshal(encoded, &s)
	for i, sig := range s.Signatures {
		raw, _ := b64.DecodeString(sig.Protected)
		if !strings.HasPrefix(string(raw), `{"typ":"vnd.consequenceos.receipt.v1+json"`) {
			t.Errorf("signature %d header = %s", i+1, raw)
		}
	}
}

func TestIssueRejectsHalfAV1(t *testing.T) {
	h := newHarness(t)
	c := configConsequence
	for name, in := range map[string]Input{
		"audience without consequence": {Tool: "x", ParamsHash: "sha256:00", Audience: "payments-api"},
		"consequence without audience": {Tool: "x", ParamsHash: "sha256:00", Consequence: &c},
	} {
		if _, _, err := h.issuer.Issue(in); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestV1PayloadFitsDraftContentRules(t *testing.T) {
	h := newHarness(t)
	if problem := draftContentProblem(payloadOf(t, h.issueV1(t, "payments-api")), 1); problem != "" {
		t.Error(problem)
	}
}

func TestV1Rejects(t *testing.T) {
	tests := []struct {
		name    string
		receipt func(t *testing.T, h harness) []byte
		want    error
	}{
		{
			name:    "for another receiver",
			receipt: func(t *testing.T, h harness) []byte { return h.issueV1(t, "staging-payments") },
			want:    verify.ErrWrongAudience,
		},
		{
			name: "a v1 payload signed as v0",
			receipt: func(t *testing.T, h harness) []byte {
				return h.signPayload(t, payloadOf(t, h.issueV1(t, "payments-api")), verify.MediaType)
			},
			want: verify.ErrMalformed,
		},
		{
			name: "a v0 payload signed as v1",
			receipt: func(t *testing.T, h harness) []byte {
				return h.signPayload(t, payloadOf(t, h.issue(t, "")), verify.MediaTypeV1)
			},
			want: verify.ErrMalformed,
		},
		{
			name: "a v0 receipt naming an audience",
			receipt: func(t *testing.T, h harness) []byte {
				p := payloadOf(t, h.issue(t, ""))
				p["audience"] = "payments-api"
				return h.signPayload(t, p, verify.MediaType)
			},
			want: verify.ErrMalformed,
		},
		{
			name: "a v1 receipt without an audience",
			receipt: func(t *testing.T, h harness) []byte {
				p := payloadOf(t, h.issueV1(t, "payments-api"))
				delete(p, "audience")
				return h.signPayload(t, p, verify.MediaTypeV1)
			},
			want: verify.ErrMalformed,
		},
		{
			name: "a v1 receipt without a consequence",
			receipt: func(t *testing.T, h harness) []byte {
				p := payloadOf(t, h.issueV1(t, "payments-api"))
				delete(p, "consequence")
				return h.signPayload(t, p, verify.MediaTypeV1)
			},
			want: verify.ErrMalformed,
		},
		{
			name: "a score over 100",
			receipt: func(t *testing.T, h harness) []byte {
				p := payloadOf(t, h.issueV1(t, "payments-api"))
				p["consequence"].(map[string]any)["score"] = 101
				return h.signPayload(t, p, verify.MediaTypeV1)
			},
			want: verify.ErrMalformed,
		},
		{
			name: "a map consequence without its hash",
			receipt: func(t *testing.T, h harness) []byte {
				p := payloadOf(t, h.issueV1(t, "payments-api"))
				p["consequence"].(map[string]any)["source"] = verify.SourceMap
				return h.signPayload(t, p, verify.MediaTypeV1)
			},
			want: verify.ErrMalformed,
		},
		{
			name: "an unknown field",
			receipt: func(t *testing.T, h harness) []byte {
				p := payloadOf(t, h.issueV1(t, "payments-api"))
				p["single_use"] = "yes"
				return h.signPayload(t, p, verify.MediaTypeV1)
			},
			want: verify.ErrMalformed,
		},
		{
			name: "signatures of two versions",
			receipt: func(t *testing.T, h harness) []byte {
				v0 := h.issue(t, "")
				return mutate(t, h.issueV1(t, "payments-api"), func(s *verify.Signed) {
					var other verify.Signed
					_ = json.Unmarshal(v0, &other)
					s.Signatures[1] = other.Signatures[1]
				})
			},
			want: verify.ErrMalformed,
		},
		{
			name: "an audit head passed as a receipt",
			receipt: func(t *testing.T, h harness) []byte {
				head, _ := h.keys.SignAuditHead("http://cos.test", 1, "sha256:"+strings.Repeat("ab", 32), testStart)
				return head
			},
			want: verify.ErrMalformed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			_, err := h.checker.Verify(context.Background(), "payments-api", tt.receipt(t, h), "purchase_order.confirm", []byte(args))
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// Before v1, any receiver with a key could use up any receipt. A v1 receipt
// can only be used by the receiver it names.
func TestWrongReceiverCannotBurnAV1Receipt(t *testing.T) {
	h := newHarness(t)
	receipt := h.issueV1(t, "payments-api")
	if _, err := h.checker.Verify(context.Background(), "staging-payments", receipt, "purchase_order.confirm", []byte(args)); !errors.Is(err, verify.ErrWrongAudience) {
		t.Fatalf("other receiver: err = %v, want ErrWrongAudience", err)
	}
	if _, err := h.checker.Verify(context.Background(), "payments-api", receipt, "purchase_order.confirm", []byte(args)); err != nil {
		t.Errorf("the right receiver can't use it after a wrong one tried: %v", err)
	}
}

func TestOfflineAudience(t *testing.T) {
	h := newHarness(t)
	jwks, _ := json.Marshal(h.keys.JWKS())
	keys, err := verify.ParseJWKS(jwks)
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return *h.clock }
	tests := []struct {
		name     string
		receipt  []byte
		audience string
		want     error
	}{
		{"v1 for this receiver", h.issueV1(t, "payments-api"), "payments-api", nil},
		{"v1 for another receiver", h.issueV1(t, "payments-api"), "staging-payments", verify.ErrWrongAudience},
		{"v1 with no audience set", h.issueV1(t, "payments-api"), "", verify.ErrWrongAudience},
		{"v0 is still accepted", h.issue(t, ""), "payments-api", nil},
		{"v0 without an audience set too", h.issue(t, ""), "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &verify.Offline{Keys: keys, Audience: tt.audience, Now: now}
			if _, err := v.Verify(context.Background(), tt.receipt, "purchase_order.confirm", []byte(args)); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// The verify endpoint takes the audience from the receiver's API key.
func TestVerifyEndpointChecksAudience(t *testing.T) {
	h := newHarness(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(VerifyHandler(h.checker, map[string]string{"pay-key": "payments-api", "stage-key": "staging-payments"}, log))
	defer srv.Close()

	receipt := h.issueV1(t, "payments-api")
	_, err := verify.NewClient(srv.URL, "stage-key").Verify(context.Background(), receipt, "purchase_order.confirm", []byte(args))
	if !errors.Is(err, verify.ErrWrongAudience) {
		t.Errorf("staging receiver: err = %v, want ErrWrongAudience", err)
	}
	r, err := verify.NewClient(srv.URL, "pay-key").Verify(context.Background(), receipt, "purchase_order.confirm", []byte(args))
	if err != nil {
		t.Fatalf("payments receiver: %v", err)
	}
	if r.Audience != "payments-api" || r.Consequence == nil || r.Consequence.Score != 80 {
		t.Errorf("the client lost v1 fields: %+v", r)
	}

	// The answer names the reason, for receivers in other languages.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+verify.VerifyPath, strings.NewReader(
		`{"receipt":`+string(h.issueV1(t, "payments-api"))+`,"tool":"purchase_order.confirm","arguments":`+args+`}`))
	req.Header.Set("Authorization", "Bearer stage-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out verify.VerifyResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Valid || out.Reason != "wrong_audience" {
		t.Errorf("got %+v, want valid false with reason wrong_audience", out)
	}
}

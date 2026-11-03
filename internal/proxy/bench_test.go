package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// These benchmarks measure what the proxy adds to a tool call. Compare
// BenchmarkUpstreamDirect (the agent calling the tool server itself) with
// BenchmarkAllowedCall (the same call through the proxy, which checks the
// policy, signs a receipt with both keys, audits and forwards).
//
//	go test -run '^$' -bench . -benchmem ./internal/proxy/

const benchArgs = `{"charge_id":"ch_1","amount":20}`

func BenchmarkUpstreamDirect(b *testing.B) {
	f := newFixture(b, nil)
	body := call("payments.refund", benchArgs)
	for b.Loop() { // b.Loop (Go 1.24+) times only the loop, not the setup above
		resp, err := http.Post(f.upstreamURL, "application/json", strings.NewReader(body))
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}

func BenchmarkAllowedCall(b *testing.B) {
	f := newFixture(b, nil)
	body := call("payments.refund", benchArgs)
	for b.Loop() {
		if rec := f.do(http.MethodPost, body, nil); rec.Code != http.StatusOK {
			b.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	}
}

// BenchmarkDeniedCall is the policy path alone: no receipt, no upstream.
func BenchmarkDeniedCall(b *testing.B) {
	f := newFixture(b, nil)
	body := call("db.delete_users", `{}`)
	for b.Loop() {
		if rec := f.do(http.MethodPost, body, nil); rec.Code != http.StatusOK {
			b.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	}
}

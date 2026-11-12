package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/matutozi/consequence-os/internal/audit"
)

const upstreamToken = "ghp_SECRETtoken1234567890"

// echoUpstream answers every request with the Authorization header it got,
// in a header and in the body, gzipped when the request allows it: the
// worst an upstream can do with the token.
type echoUpstream struct {
	mu   sync.Mutex
	auth []string // the Authorization header of each request
}

func (u *echoUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	got := r.Header.Get("Authorization")
	u.mu.Lock()
	u.auth = append(u.auth, got)
	u.mu.Unlock()
	// Repeated, so gzip really compresses it: a short body would be stored
	// as is, token and all, inside the gzip stream.
	body := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"you sent ` + strings.Repeat(got+" ", 8) + `"}],"isError":false}}`
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Debug-Auth", got)
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz, _ := gzip.NewWriterLevel(w, gzip.BestCompression)
		_, _ = io.WriteString(gz, body)
		_ = gz.Close()
		return
	}
	_, _ = io.WriteString(w, body)
}

func (u *echoUpstream) seen() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.auth...)
}

// withUpstreamAuth rebuilds the fixture's proxy in front of an echoing
// upstream, with a token, logging to logs.
func withUpstreamAuth(t *testing.T, f *fixture, logs io.Writer) *echoUpstream {
	t.Helper()
	up := &echoUpstream{}
	srv := httptest.NewServer(up)
	t.Cleanup(srv.Close)
	opts := f.opts
	opts.Upstream, opts.UpstreamAuth = srv.URL+"/mcp", upstreamToken
	opts.Log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	f.proxy = p
	return up
}

func TestUpstreamAuth(t *testing.T) {
	f := newFixture(t, nil)
	var logs syncBuffer
	up := withUpstreamAuth(t, &f, &logs)

	requests := []struct {
		name, method, body string
		headers            map[string]string
	}{
		{"an allowed tool call", http.MethodPost, call("payments.refund", `{"charge_id":"ch_1","amount":20}`), nil},
		{"a read", http.MethodPost, call("notes.read", `{}`), nil},
		{"passthrough", http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil},
		{"an event stream", http.MethodGet, "", nil},
		{"asking for gzip", http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, map[string]string{"Accept-Encoding": "gzip"}},
	}
	for _, tt := range requests {
		t.Run(tt.name, func(t *testing.T) {
			rec := f.do(tt.method, tt.body, tt.headers)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			if got := up.seen(); got[len(got)-1] != "Bearer "+upstreamToken {
				t.Errorf("upstream got Authorization %q, want the token", got[len(got)-1])
			}
			body := rec.Body.String()
			if ce := rec.Header().Get("Content-Encoding"); ce != "" {
				t.Fatalf("the agent got a %s body, which the token can't be scrubbed from", ce)
			}
			if strings.Contains(body, upstreamToken) || strings.Contains(rec.Header().Get("X-Debug-Auth"), upstreamToken) {
				t.Errorf("the token reached the agent: %s %v", body, rec.Header())
			}
			if !strings.Contains(body, "you sent Bearer "+strings.Repeat("*", len(upstreamToken))) {
				t.Errorf("body = %q, want the token masked", body)
			}
			if n := rec.Header().Get("Content-Length"); n != "" && n != itoa(len(body)) {
				t.Errorf("Content-Length %s, body is %d bytes", n, len(body))
			}
		})
	}

	// A held call isn't forwarded at all.
	before := len(up.seen())
	f.do(http.MethodPost, call("payments.refund", `{"charge_id":"ch_1","amount":5000}`), nil)
	if len(up.seen()) != before {
		t.Error("a held call reached the upstream")
	}
	for _, a := range up.seen() {
		if strings.Contains(a, agentKey) {
			t.Errorf("the upstream saw the agent's key: %q", a)
		}
	}

	// Nothing written down holds the token.
	entries, _ := f.store.ListAudit(context.Background(), audit.Filter{})
	raw, _ := json.Marshal(entries)
	if bytes.Contains(raw, []byte(upstreamToken)) {
		t.Error("the audit log holds the token")
	}
	if strings.Contains(logs.String(), upstreamToken) {
		t.Errorf("a log line holds the token:\n%s", logs.String())
	}
}

func TestUpstreamAuthNotLoggedWhenTheUpstreamFails(t *testing.T) {
	f := newFixture(t, nil)
	var logs syncBuffer
	withUpstreamAuth(t, &f, &logs)
	opts := f.opts
	opts.Upstream, opts.UpstreamAuth = "http://127.0.0.1:1/mcp", upstreamToken // nothing listens there
	opts.Log = slog.New(slog.NewTextHandler(&logs, nil))
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	f.proxy = p
	if rec := f.do(http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil); rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(logs.String(), "upstream request failed") || strings.Contains(logs.String(), upstreamToken) {
		t.Errorf("logs:\n%s", logs.String())
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestRedactor(t *testing.T) {
	const secret = "s3cr3t"
	mask := strings.Repeat("*", len(secret))
	tests := []struct{ in, want string }{
		{"no secret here", "no secret here"},
		{"s3cr3t", mask},
		{"a s3cr3t and s3cr3t again", "a " + mask + " and " + mask + " again"},
		{"ends with the start s3c", "ends with the start s3c"}, // held back, then let go at the end
		{"s3cr3s3cr3t", "s3cr3" + mask},
		{"", ""},
	}
	readers := map[string]func(string) io.Reader{
		"whole":       func(s string) io.Reader { return strings.NewReader(s) },
		"byte a time": func(s string) io.Reader { return iotest.OneByteReader(strings.NewReader(s)) },
		"half":        func(s string) io.Reader { return iotest.HalfReader(strings.NewReader(s)) },
		"data and EOF": func(s string) io.Reader {
			return iotest.DataErrReader(strings.NewReader(s))
		},
	}
	for name, mk := range readers {
		for _, tt := range tests {
			got, err := io.ReadAll(newRedactor(io.NopCloser(mk(tt.in)), secret))
			if err != nil || string(got) != tt.want {
				t.Errorf("%s, %q: got %q, %v; want %q", name, tt.in, got, err, tt.want)
			}
		}
	}
}

// An event that ends the way SSE events do must come out at once, not
// wait for more bytes in case they complete the secret.
func TestRedactorDoesNotDelayEvents(t *testing.T) {
	pr, pw := io.Pipe()
	r := newRedactor(pr, "s3cr3t")
	go func() { _, _ = io.WriteString(pw, "data: {\"x\":1}\n\n") }() // and then nothing, for now
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := r.Read(buf)
		got <- string(buf[:n])
	}()
	select {
	case s := <-got:
		if s != "data: {\"x\":1}\n\n" {
			t.Errorf("got %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the event was held back")
	}
	pw.Close()
}

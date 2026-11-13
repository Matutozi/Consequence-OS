package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/receipt"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// fakeChain is the Agent Registry in memory. It decodes the parameters the
// tool sends and enforces what the deployed contract does: only an agent's
// owner may change it, and metadata values are at most 485 bytes, with no
// zero byte.
type fakeChain struct {
	mu     sync.Mutex
	acct   string // "" for queries only
	agents map[uint64]*fakeAgent
	next   uint64
	sent   []string // the entrypoints of the transactions sent
}

type fakeAgent struct {
	owner   string
	uri     string
	hash    *[32]byte
	revoked bool
	meta    map[string][]byte
}

const (
	ownerAccount = "3dt3UMPzRASZndjmKpSWgCP2HhmoxZrgs8FDPtZjNHZzj13hhB"
	otherAccount = "3whdieGHx43KKRwQYbC5pAUdmWZ61B7yreNRU9i36MtdCvajR8"
	codeNotOwner = -42 // the fake's; the registry's own codes aren't documented
)

func newFakeChain(acct string) *fakeChain {
	return &fakeChain{acct: acct, agents: map[uint64]*fakeAgent{}, next: 7}
}

func (f *fakeChain) account() string { return f.acct }

func mustAccount(s string) []byte {
	b, err := accountBytes(s)
	if err != nil {
		panic(err)
	}
	return b
}

func (f *fakeChain) view(_ context.Context, entrypoint string, param []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := reader{b: param}
	id := r.tokenID()
	a := f.agents[id]
	switch entrypoint {
	case "agentOf":
		if a == nil {
			return []byte{0}, r.err
		}
		b := appendTokenID([]byte{1}, id)
		b = append(b, mustAccount(a.owner)...)
		if a.uri == "" {
			b = append(b, 0)
		} else {
			b = appendBytes(append(b, 1), []byte(a.uri))
		}
		if a.hash == nil {
			b = append(b, 0)
		} else {
			b = append(append(b, 1), a.hash[:]...)
		}
		b = append(b, 0)                                  // no external reference
		b = append(append(b, 1), mustAccount(a.owner)...) // the wallet
		status := byte(statusActive)
		if a.revoked {
			status = statusRevoked
		}
		b = append(b, status)
		b = binary.LittleEndian.AppendUint64(b, uint64(time.Now().UnixMilli()))
		return append(b, make([]byte, 6)...), r.err
	case "getMetadata":
		key := string(r.vec())
		if a == nil {
			return nil, &rejectedError{Entrypoint: entrypoint, Code: -1}
		}
		v, ok := a.meta[key]
		if !ok {
			return []byte{0}, r.err
		}
		return appendBytes([]byte{1}, v), r.err
	}
	return nil, fmt.Errorf("the fake has no %s", entrypoint)
}

func (f *fakeChain) update(_ context.Context, entrypoint string, param []byte) (txResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acct == "" {
		return txResult{}, errNoAccount
	}
	reject := func(code int32) (txResult, error) {
		return txResult{}, &rejectedError{Entrypoint: entrypoint, Code: code}
	}
	r := reader{b: param}
	var events [][]byte
	switch entrypoint {
	case "register":
		a := &fakeAgent{owner: f.acct, meta: map[string][]byte{}}
		if r.option() {
			a.uri = string(r.vec())
		}
		if r.option() {
			a.hash = (*[32]byte)(bytes.Clone(r.take(32)))
		}
		r.option()
		r.u32()
		if r.err != nil || len(r.b) > 0 {
			return reject(-2147483648)
		}
		id := f.next
		f.next++
		f.agents[id] = a
		mint := appendTokenID([]byte{0xfe}, id)
		mint = append(append(mint, 1, 0), mustAccount(f.acct)...)
		events = append(events, []byte{0xf0, 1, 2}, mint) // the registry's own event, then CIS-2's mint
	case "setAgentURI", "setMetadata":
		id := r.tokenID()
		a := f.agents[id]
		if a == nil || a.owner != f.acct || a.revoked {
			return reject(codeNotOwner)
		}
		if entrypoint == "setAgentURI" {
			r.option()
			a.uri = string(r.vec())
			r.option()
			a.hash = (*[32]byte)(bytes.Clone(r.take(32)))
			break
		}
		key, value := string(r.vec()), r.vec()
		switch {
		case r.err != nil || len(r.b) > 0 || len(value) > maxMetadataValue:
			return reject(-2147483648)
		case bytes.IndexByte(value, 0) >= 0:
			return reject(-7208)
		}
		a.meta[key] = bytes.Clone(value)
	default:
		return txResult{}, fmt.Errorf("the fake has no %s", entrypoint)
	}
	f.sent = append(f.sent, entrypoint)
	return txResult{Hash: fmt.Sprintf("%064x", len(f.sent)), Events: events}, nil
}

// testLog is a ConsequenceOS audit log, chained as the stores chain it.
type testLog struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (l *testLog) add(t *testing.T, n int) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	for range n {
		prev := ""
		if len(l.entries) > 0 {
			prev = l.entries[len(l.entries)-1].Hash
		}
		seq := int64(len(l.entries) + 1)
		e, err := audit.Chain(prev, audit.Entry{
			ID: fmt.Sprintf("aud_%d", seq), Time: time.Date(2026, 11, 13, 9, 0, int(seq), 0, time.UTC),
			AgentID: "bot", Tool: "payments.refund", Decision: policy.ActionAllow, Outcome: audit.OutcomeForwarded,
		})
		if err != nil {
			t.Fatal(err)
		}
		e.Seq = seq
		l.entries = append(l.entries, e)
	}
}

// rewrite changes entry i and re-chains everything after it, as someone
// with database access could: the chain checks out, but not against a
// head saved before.
func (l *testLog) rewrite(t *testing.T, i int) {
	t.Helper()
	l.mu.Lock()
	old := l.entries
	l.entries = nil
	l.mu.Unlock()
	for j, e := range old {
		if j == i {
			e.Tool = "payments.refund.rewritten"
		}
		prev := ""
		if j > 0 {
			prev = l.entries[j-1].Hash
		}
		c, err := audit.Chain(prev, audit.Entry{ID: e.ID, Time: e.Time, AgentID: e.AgentID, Tool: e.Tool, Decision: e.Decision, Outcome: e.Outcome})
		if err != nil {
			t.Fatal(err)
		}
		c.Seq = e.Seq
		l.entries = append(l.entries, c)
	}
}

func (l *testLog) cut(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = l.entries[:n]
}

func (l *testLog) ForEachAudit(_ context.Context, fn func(audit.Entry) error) error {
	l.mu.Lock()
	entries := append([]audit.Entry(nil), l.entries...)
	l.mu.Unlock()
	for _, e := range entries {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func (l *testLog) LastAudit(context.Context) (audit.Entry, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 {
		return audit.Entry{}, false, nil
	}
	return l.entries[len(l.entries)-1], true, nil
}

const adminToken = "admin-secret"

func testKeys(t *testing.T) *receipt.Keys {
	t.Helper()
	ed, ml, err := receipt.GenerateSeeds()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := receipt.LoadKeys(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// env is a ConsequenceOS server with a log, a place to host cards, and the
// registry, wired up as consequenced and a card host would be.
type env struct {
	t      *testing.T
	log    *testLog
	keys   *receipt.Keys
	srv    *httptest.Server
	chain  *fakeChain
	cards  map[string][]byte // path → what the card host serves
	mu     sync.Mutex
	out    bytes.Buffer
	heads  string
	issuer string // what the server signs heads as; its URL unless a test changes it
}

func newEnv(t *testing.T) *env {
	e := &env{t: t, log: &testLog{}, keys: testKeys(t), chain: newFakeChain(ownerAccount), cards: map[string][]byte{}, heads: filepath.Join(t.TempDir(), "heads")}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	mux := http.NewServeMux()
	sign := func(seq int64, hash string) ([]byte, error) {
		return e.keys.SignAuditHead(e.issuer, seq, hash, time.Now())
	}
	mux.Handle("GET /v1/audit/head", audit.HeadHandler(e.log, sign, adminToken, quiet))
	mux.Handle("GET /v1/audit/verify", audit.VerifyHandler(e.log, nil, adminToken, quiet))
	mux.Handle("GET "+verify.KeysPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receipt.KeysHandler(e.keys).ServeHTTP(w, r)
	}))
	mux.HandleFunc("GET /cards/", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		card, ok := e.cards[r.URL.Path]
		e.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(card)
	})
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	e.issuer = e.srv.URL
	e.log.add(t, 3)
	return e
}

func (e *env) tool() tool {
	return tool{
		reg:  registry{c: e.chain, net: networks["testnet"]},
		srv:  guardServer{base: e.srv.URL, token: adminToken, http: e.srv.Client()},
		http: e.srv.Client(),
		out:  &e.out,
	}
}

// host serves card at /cards/name and returns its URL.
func (e *env) host(name string, card []byte) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cards["/cards/"+name] = card
	return e.srv.URL + "/cards/" + name
}

// registered registers an agent with a card naming this server as its
// guard, the way the docs walk through it, and returns its ID.
func (e *env) registered() uint64 {
	e.t.Helper()
	ctx := context.Background()
	tl := e.tool()
	if err := tl.register(ctx, ""); err != nil {
		e.t.Fatal(err)
	}
	id := e.chain.next - 1
	uri := e.srv.URL + fmt.Sprintf("/cards/agent-%d.json", id)
	card, err := buildCard(cardInput{Name: "Refund bot", Description: "Issues refunds, guarded", URL: uri, Owner: ownerAccount, TokenID: &id, Issuer: e.srv.URL, Net: networks["testnet"]})
	if err != nil {
		e.t.Fatal(err)
	}
	e.host(fmt.Sprintf("agent-%d.json", id), card)
	if err := tl.setCard(ctx, id, uri, ""); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) anchored(id uint64) anchorValue {
	e.t.Helper()
	v, ok := e.chain.agents[id].meta[anchorKey]
	if !ok {
		e.t.Fatal("nothing anchored")
	}
	a, err := decodeAnchor(v)
	if err != nil {
		e.t.Fatal(err)
	}
	return a
}

func TestAnchorAndVerify(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	id := e.registered()
	if !strings.Contains(e.out.String(), "badge:       "+tokenAddress(networks["testnet"].Registry, id)) {
		t.Errorf("register didn't print the badge:\n%s", e.out.String())
	}

	sent, err := e.tool().anchor(ctx, id, e.heads)
	if err != nil || !sent {
		t.Fatalf("first anchor: %v, %v\n%s", sent, err, e.out.String())
	}
	a := e.anchored(id)
	if a.Seq != 3 || a.Hash != e.log.entries[2].Hash {
		t.Errorf("anchored %+v, want entry 3, %s", a, e.log.entries[2].Hash)
	}
	headFile := filepath.Join(e.heads, "head-3.json")
	signed, err := os.ReadFile(headFile)
	if err != nil {
		t.Fatal(err)
	}
	if digest(signed) != a.Head {
		t.Error("the saved head isn't the one anchored")
	}
	if raw := e.chain.agents[id].meta[anchorKey]; len(raw) > 200 {
		t.Errorf("the anchor is %d bytes: %s", len(raw), raw)
	}

	// Nothing new: nothing sent.
	before := len(e.chain.sent)
	if sent, err := e.tool().anchor(ctx, id, e.heads); err != nil || sent || len(e.chain.sent) != before {
		t.Errorf("anchoring the same head again: sent %v, %v", sent, err)
	}

	// New entries: anchored, after the server held the log to entry 3.
	e.log.add(t, 2)
	if sent, err := e.tool().anchor(ctx, id, e.heads); err != nil || !sent {
		t.Fatalf("second anchor: %v, %v", sent, err)
	}
	if a := e.anchored(id); a.Seq != 5 {
		t.Errorf("anchored entry %d, want 5", a.Seq)
	}

	// Anyone can check it, without keys or the admin token.
	e.out.Reset()
	reader := e.tool()
	reader.reg.c = &queryOnly{e.chain}
	if err := reader.verifyAgent(ctx, id, filepath.Join(e.heads, "head-5.json"), ""); err != nil {
		t.Fatalf("verify: %v\n%s", err, e.out.String())
	}
	for _, want := range []string{"status: active", "matches the SHA-256 the registry pinned", "guard:  ConsequenceOS at " + e.srv.URL, "anchor: entry 5", "is the anchored head, signed by " + e.srv.URL, "consequenced -verify-audit -audit-head", "\nok\n"} {
		if !strings.Contains(e.out.String(), want) {
			t.Errorf("verify didn't say %q:\n%s", want, e.out.String())
		}
	}
}

// queryOnly is the registry as seen without keys.
type queryOnly struct{ c *fakeChain }

func (q *queryOnly) view(ctx context.Context, ep string, p []byte) ([]byte, error) {
	return q.c.view(ctx, ep, p)
}
func (q *queryOnly) update(context.Context, string, []byte) (txResult, error) {
	return txResult{}, errNoAccount
}
func (q *queryOnly) account() string { return "" }

func TestAnchorRefusesALogThatDoesntHoldUp(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(e *env){
		"cut back":         func(e *env) { e.log.cut(2) },
		"cut and regrown":  func(e *env) { e.log.cut(2); e.log.add(e.t, 3); e.log.rewrite(e.t, 2) },
		"rewritten":        func(e *env) { e.log.rewrite(e.t, 1) },
		"rewritten at end": func(e *env) { e.log.rewrite(e.t, 2) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			id := e.registered()
			if _, err := e.tool().anchor(ctx, id, e.heads); err != nil {
				t.Fatal(err)
			}
			held := e.anchored(id)
			change(e)
			before := len(e.chain.sent)
			_, err := e.tool().anchor(ctx, id, e.heads)
			var r *refusal
			if !errors.As(err, &r) || !strings.Contains(err.Error(), "doesn't hold up") || !strings.Contains(err.Error(), "stays as evidence") {
				t.Fatalf("got %v, want a refusal", err)
			}
			if len(e.chain.sent) != before || e.anchored(id) != held {
				t.Error("something was anchored over a log that doesn't hold up")
			}
			// -every stops rather than carry on.
			done := make(chan error, 1)
			go func() { done <- e.tool().anchorEvery(ctx, id, e.heads, time.Hour) }()
			select {
			case err := <-done:
				if !errors.As(err, &r) {
					t.Errorf("-every ended with %v, want the refusal", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("-every kept going over a log that doesn't hold up")
			}
		})
	}
}

func TestAnchorRefusesTheWrongServer(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	id := e.registered()
	e.issuer = "https://someone-else.example"
	if _, err := e.tool().anchor(ctx, id, e.heads); err == nil || !strings.Contains(err.Error(), "signs as https://someone-else.example") {
		t.Errorf("got %v", err)
	}
	if len(e.chain.agents[id].meta) != 0 {
		t.Error("anchored another server's log")
	}
}

func TestAnchorChecksTheHeadsSignature(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	id := e.registered()
	// A server that signs heads with one pair of keys and publishes another.
	signing, published := e.keys, testKeys(t)
	srv := e.tool()
	mux := http.NewServeMux()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	mux.Handle("GET /v1/audit/head", audit.HeadHandler(e.log, func(seq int64, hash string) ([]byte, error) {
		return signing.SignAuditHead(e.issuer, seq, hash, time.Now())
	}, adminToken, quiet))
	mux.Handle("GET /v1/audit/verify", audit.VerifyHandler(e.log, nil, adminToken, quiet))
	mux.Handle("GET "+verify.KeysPath, receipt.KeysHandler(published))
	other := httptest.NewServer(mux)
	defer other.Close()
	srv.srv = guardServer{base: other.URL, token: adminToken, http: other.Client()}
	if _, err := srv.anchor(ctx, id, e.heads); err == nil || !strings.Contains(err.Error(), "doesn't check out with its own keys") {
		t.Errorf("got %v", err)
	}
	if len(e.chain.agents[id].meta) != 0 {
		t.Error("anchored a head that doesn't verify")
	}
}

func TestAnchorRefusesBeforeSending(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	id := e.registered()

	e.chain.agents[id].owner = otherAccount
	if _, err := e.tool().anchor(ctx, id, e.heads); err == nil || !strings.Contains(err.Error(), "is owned by "+otherAccount) {
		t.Errorf("someone else's agent: %v", err)
	}
	e.chain.agents[id].owner = ownerAccount

	e.chain.agents[id].revoked = true
	if _, err := e.tool().anchor(ctx, id, e.heads); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("a revoked agent: %v", err)
	}
	e.chain.agents[id].revoked = false

	if _, err := e.tool().anchor(ctx, 999, e.heads); err == nil || !strings.Contains(err.Error(), "no agent 999") {
		t.Errorf("no such agent: %v", err)
	}

	e.chain.agents[id].meta[anchorKey] = []byte("not an anchor")
	if _, err := e.tool().anchor(ctx, id, e.heads); err == nil || !strings.Contains(err.Error(), "isn't an anchor this tool wrote") {
		t.Errorf("something else under the key: %v", err)
	}
	delete(e.chain.agents[id].meta, anchorKey)

	// The card changed since it was pinned.
	e.host(fmt.Sprintf("agent-%d.json", id), []byte(`{"changed":true}`))
	if _, err := e.tool().anchor(ctx, id, e.heads); err == nil || !strings.Contains(err.Error(), "isn't the one the registry pinned") {
		t.Errorf("a changed card: %v", err)
	}
	if len(e.chain.agents[id].meta) != 0 {
		t.Error("anchored despite a refusal")
	}

	bad := e.tool()
	bad.srv.token = "wrong"
	e.registered() // a fresh agent with a good card
	if _, err := bad.anchor(ctx, id+1, e.heads); err == nil || !strings.Contains(err.Error(), "admin token required") {
		t.Errorf("a wrong admin token: %v", err)
	}
}

func TestSaveHeadNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	if _, err := saveHead(dir, 4, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := saveHead(dir, 4, []byte("one")); err != nil {
		t.Errorf("saving the same head again: %v", err)
	}
	if _, err := saveHead(dir, 4, []byte("two")); err == nil {
		t.Error("a different head for the same entry overwrote the first")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "head-4.json")); string(b) != "one" {
		t.Errorf("the head file holds %q", b)
	}
}

func TestVerifyFindsProblems(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*env, uint64, string) {
		e := newEnv(t)
		id := e.registered()
		if _, err := e.tool().anchor(ctx, id, e.heads); err != nil {
			t.Fatal(err)
		}
		e.out.Reset()
		return e, id, filepath.Join(e.heads, "head-3.json")
	}
	tests := []struct {
		name   string
		change func(e *env, id uint64, head string) (headArg, keysArg string)
		want   string
	}{
		{"revoked", func(e *env, id uint64, head string) (string, string) {
			e.chain.agents[id].revoked = true
			return head, ""
		}, "the agent was revoked"},
		{"card changed", func(e *env, id uint64, head string) (string, string) {
			e.host(fmt.Sprintf("agent-%d.json", id), []byte("{}"))
			return head, ""
		}, "DOESN'T MATCH"},
		{"card gone", func(e *env, id uint64, head string) (string, string) {
			e.mu.Lock()
			delete(e.cards, fmt.Sprintf("/cards/agent-%d.json", id))
			e.mu.Unlock()
			return head, ""
		}, "COULDN'T BE FETCHED"},
		{"card not pinned", func(e *env, id uint64, head string) (string, string) {
			e.chain.agents[id].hash = nil
			return head, ""
		}, "holds no SHA-256 for the card"},
		{"no card", func(e *env, id uint64, head string) (string, string) {
			e.chain.agents[id].uri = ""
			return head, e.srv.URL + verify.KeysPath
		}, "has no card"},
		{"nothing anchored", func(e *env, id uint64, head string) (string, string) {
			delete(e.chain.agents[id].meta, anchorKey)
			return head, ""
		}, "nothing is anchored"},
		{"another head", func(e *env, id uint64, head string) (string, string) {
			other := filepath.Join(e.t.TempDir(), "h.json")
			_ = os.WriteFile(other, []byte(`{"not":"it"}`), 0o644)
			return other, ""
		}, "isn't the anchored head"},
		{"head signed by other keys", func(e *env, id uint64, head string) (string, string) {
			// A head for the anchored entry, signed by keys the card doesn't name,
			// and anchored in its place.
			forged, _ := testKeys(e.t).SignAuditHead(e.srv.URL, 3, e.log.entries[2].Hash, time.Now())
			path := filepath.Join(e.t.TempDir(), "forged.json")
			_ = os.WriteFile(path, forged, 0o644)
			v, _ := encodeAnchor(anchorValue{Seq: 3, Hash: e.log.entries[2].Hash, Head: digest(forged)})
			e.chain.agents[id].meta[anchorKey] = v
			return path, ""
		}, "doesn't verify with the keys at"},
		{"head for another entry", func(e *env, id uint64, head string) (string, string) {
			other, _ := e.keys.SignAuditHead(e.srv.URL, 2, e.log.entries[1].Hash, time.Now())
			path := filepath.Join(e.t.TempDir(), "other.json")
			_ = os.WriteFile(path, other, 0o644)
			v, _ := encodeAnchor(anchorValue{Seq: 3, Hash: e.log.entries[2].Hash, Head: digest(other)})
			e.chain.agents[id].meta[anchorKey] = v
			return path, ""
		}, "names entry 2"},
		{"head with another hash", func(e *env, id uint64, head string) (string, string) {
			other, _ := e.keys.SignAuditHead(e.srv.URL, 3, e.log.entries[1].Hash, time.Now())
			path := filepath.Join(e.t.TempDir(), "other.json")
			_ = os.WriteFile(path, other, 0o644)
			v, _ := encodeAnchor(anchorValue{Seq: 3, Hash: e.log.entries[2].Hash, Head: digest(other)})
			e.chain.agents[id].meta[anchorKey] = v
			return path, ""
		}, "names entry 3 ("},
		{"head from another issuer", func(e *env, id uint64, head string) (string, string) {
			other, _ := e.keys.SignAuditHead("https://elsewhere.example", 3, e.log.entries[2].Hash, time.Now())
			path := filepath.Join(e.t.TempDir(), "other.json")
			_ = os.WriteFile(path, other, 0o644)
			v, _ := encodeAnchor(anchorValue{Seq: 3, Hash: e.log.entries[2].Hash, Head: digest(other)})
			e.chain.agents[id].meta[anchorKey] = v
			return path, ""
		}, "was signed by https://elsewhere.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, id, head := setup(t)
			headArg, keysArg := tt.change(e, id, head)
			err := e.tool().verifyAgent(ctx, id, headArg, keysArg)
			if err == nil || !strings.Contains(e.out.String(), "PROBLEM: ") || !strings.Contains(e.out.String(), tt.want) {
				t.Errorf("got %v, want a problem with %q:\n%s", err, tt.want, e.out.String())
			}
			if strings.Contains(e.out.String(), "\nok\n") {
				t.Errorf("said ok:\n%s", e.out.String())
			}
		})
	}
}

func TestSetCardChecksTheCard(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	id := e.registered()

	plain := e.host("plain.json", []byte(`{"name":"no guard"}`))
	if err := e.tool().setCard(ctx, id, plain, ""); err == nil || !strings.Contains(err.Error(), "doesn't say the agent is guarded") {
		t.Errorf("a card without the extension: %v", err)
	}
	card, _ := buildCard(cardInput{Name: "n", Description: "d", URL: "https://x.example/c", Owner: ownerAccount, Issuer: e.srv.URL, Net: networks["testnet"]})
	uri := e.host("new.json", card)
	local := filepath.Join(t.TempDir(), "card.json")
	_ = os.WriteFile(local, append(bytes.Clone(card), ' '), 0o644)
	if err := e.tool().setCard(ctx, id, uri, local); err == nil || !strings.Contains(err.Error(), "serves something other than") {
		t.Errorf("a URL serving another file: %v", err)
	}
	_ = os.WriteFile(local, card, 0o644)
	if err := e.tool().setCard(ctx, id, uri, local); err != nil {
		t.Fatal(err)
	}
	if a := e.chain.agents[id]; a.uri != uri || *a.hash != sha256.Sum256(card) {
		t.Errorf("pinned %s %x", a.uri, a.hash)
	}
}

func TestRegisterWithACard(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	card, _ := buildCard(cardInput{Name: "n", Description: "d", URL: "https://x.example/c", Owner: ownerAccount, Issuer: e.srv.URL, Net: networks["testnet"]})
	uri := e.host("pre.json", card)
	if err := e.tool().register(ctx, uri); err != nil {
		t.Fatal(err)
	}
	a := e.chain.agents[e.chain.next-1]
	if a.uri != uri || a.hash == nil || *a.hash != sha256.Sum256(card) {
		t.Errorf("registered %+v", a)
	}
	none := newEnv(t)
	none.chain.acct = ""
	if err := none.tool().register(ctx, ""); !errors.Is(err, errNoAccount) {
		t.Errorf("without keys: %v", err)
	}
}

// lyingServer says its log is intact, but serves a head from another log:
// the checks after the server's own must catch it.
func TestAnchorDoesntTakeTheServersWordAlone(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(e *env) *testLog{
		"went back": func(e *env) *testLog { l := &testLog{}; l.add(e.t, 2); return l },
		"forked":    func(e *env) *testLog { l := &testLog{}; l.add(e.t, 3); l.rewrite(e.t, 0); return l },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			id := e.registered()
			if _, err := e.tool().anchor(ctx, id, e.heads); err != nil {
				t.Fatal(err)
			}
			held := e.anchored(id)
			other := change(e)
			quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
			mux := http.NewServeMux()
			mux.Handle("GET /v1/audit/head", audit.HeadHandler(other, func(seq int64, hash string) ([]byte, error) {
				return e.keys.SignAuditHead(e.issuer, seq, hash, time.Now())
			}, adminToken, quiet))
			mux.HandleFunc("GET /v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"intact":true,"checked":1,"head_seq":1}`))
			})
			mux.Handle("GET "+verify.KeysPath, receipt.KeysHandler(e.keys))
			liar := httptest.NewServer(mux)
			defer liar.Close()
			tl := e.tool()
			tl.srv = guardServer{base: liar.URL, token: adminToken, http: liar.Client()}
			_, err := tl.anchor(ctx, id, e.heads)
			var r *refusal
			if !errors.As(err, &r) {
				t.Fatalf("got %v, want a refusal", err)
			}
			if e.anchored(id) != held {
				t.Error("anchored a head the log it was checked against doesn't lead to")
			}
		})
	}
}

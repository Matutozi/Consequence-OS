package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/policy"
)

// elicitingServer answers tool calls by asking the client something first:
// over SSE, an elicitation request then the result; or, for the tool
// "modern", a 2026-07-28 input_required result. It keeps the answers the
// proxy sends it.
type elicitingServer struct {
	mu      sync.Mutex
	ask     string // the elicitation's params
	answers []string
	session []string // the Mcp-Session-Id each answer came with
}

func (s *elicitingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	_ = json.Unmarshal(body, &m)
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.Method == "" { // an answer to our request
		s.answers = append(s.answers, string(body))
		s.session = append(s.session, r.Header.Get("Mcp-Session-Id"))
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if m.Params.Name == "modern" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"result":{"resultType":"input_required","inputRequests":{"q":{"method":"elicitation/create","params":`+s.ask+`}},"requestState":"st"}}`)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	_, _ = io.WriteString(w, "id: 1\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"e1\",\"method\":\"elicitation/create\",\"params\":"+s.ask+"}\n\n"+
		"id: 2\ndata: {\"jsonrpc\":\"2.0\",\"id\":"+string(m.ID)+",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"done\"}],\"isError\":false}}\n\n")
}

func (s *elicitingServer) got() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.answers...), append([]string(nil), s.session...)
}

func newElicitingFixture(t *testing.T, ask string) (fixture, *elicitingServer) {
	t.Helper()
	rules := append(serverRules(), policy.Rule{Name: "login", Tool: "account.*", Action: policy.ActionAllow}, policy.Rule{Name: "modern", Tool: "modern", Action: policy.ActionAllow})
	f := newFixtureWithRules(t, nil, rules)
	up := &elicitingServer{ask: ask}
	srv := httptest.NewServer(up)
	t.Cleanup(srv.Close)
	f.opts.Upstream = srv.URL
	var err error
	if f.proxy, err = New(f.opts); err != nil {
		t.Fatal(err)
	}
	return f, up
}

func TestServerRequestsOverHTTP(t *testing.T) {
	f, up := newElicitingFixture(t, phish)
	rec := f.do("POST", call("account.login", `{}`), map[string]string{"Mcp-Session-Id": "sess-42", "Accept": "application/json, text/event-stream"})
	body := rec.Body.String()
	if strings.Contains(body, "Password") || strings.Contains(body, "elicitation/create") || strings.Contains(body, "id: 1\n") {
		t.Errorf("the phishing request, or its event, reached the agent:\n%s", body)
	}
	if !strings.Contains(body, `"text":"done"`) || !strings.Contains(body, "id: 2") {
		t.Errorf("the rest of the stream was lost:\n%s", body)
	}
	// The server was told no, in the same session.
	deadline := time.Now().Add(5 * time.Second)
	var answers, sessions []string
	for time.Now().Before(deadline) {
		if answers, sessions = up.got(); len(answers) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(answers) != 1 || !strings.Contains(answers[0], `"id":"e1"`) || !strings.Contains(answers[0], `"action":"decline"`) || sessions[0] != "sess-42" {
		t.Errorf("answers the server got: %q in sessions %q", answers, sessions)
	}

	// An ordinary question passes through as it came.
	f, _ = newElicitingFixture(t, `{"message":"Which branch?","requestedSchema":{"type":"object","properties":{}}}`)
	if body := f.do("POST", call("account.login", `{}`), nil).Body.String(); !strings.Contains(body, "Which branch?") {
		t.Errorf("an ordinary question didn't reach the agent:\n%s", body)
	}
}

func TestInputRequiredOverHTTP(t *testing.T) {
	f, _ := newElicitingFixture(t, phish)
	body := f.do("POST", call("modern", `{}`), nil).Body.String()
	if strings.Contains(body, "Password") || !strings.Contains(body, `"isError":true`) || !strings.Contains(body, `policy rule \"no-password-prompts\"`) {
		t.Errorf("an input_required phishing for a password:\n%s", body)
	}
	f, _ = newElicitingFixture(t, `{"message":"Which branch?"}`)
	if body := f.do("POST", call("modern", `{}`), nil).Body.String(); !strings.Contains(body, "input_required") {
		t.Errorf("an ordinary input_required:\n%s", body)
	}
}

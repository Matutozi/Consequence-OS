package proxy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/store"
)

func askInClient(o *StdioOptions) { o.AskInClient = true }

// modernCall is a 2026-07-28 tools/call, from a client with the given
// capabilities, with extra params such as a retry's answer.
func modernCall(id int, tool, args, caps, extra string) string {
	p := `"name":"` + tool + `","arguments":` + args +
		`,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":` + caps + `}`
	if extra != "" {
		p += "," + extra
	}
	b, _ := json.Marshal(id)
	return `{"jsonrpc":"2.0","id":` + string(b) + `,"method":"tools/call","params":{` + p + `}}`
}

const formCaps = `{"elicitation":{"form":{}}}`

// question reads an input_required answer: the question and the state.
func question(t *testing.T, line string) (message, state string) {
	t.Helper()
	var r struct {
		Result struct {
			ResultType    string `json:"resultType"`
			InputRequests map[string]struct {
				Method string `json:"method"`
				Params struct {
					Mode            string         `json:"mode"`
					Message         string         `json:"message"`
					RequestedSchema map[string]any `json:"requestedSchema"`
				} `json:"params"`
			} `json:"inputRequests"`
			RequestState string `json:"requestState"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(line), &r); err != nil || r.Result.ResultType != "input_required" {
		t.Fatalf("not a question: %s", line)
	}
	q, ok := r.Result.InputRequests[askKey]
	if !ok || q.Method != "elicitation/create" || q.Params.Mode != "form" || r.Result.RequestState == "" {
		t.Fatalf("question = %+v", r.Result)
	}
	return q.Params.Message, r.Result.RequestState
}

func answer(state, action string, approve bool) string {
	b, _ := json.Marshal(state)
	return `"requestState":` + string(b) + `,"inputResponses":{"` + askKey + `":{"action":"` + action + `","content":{"approve":` + map[bool]string{true: "true", false: "false"}[approve] + `}}}`
}

func TestAskInClient(t *testing.T) {
	big := `{"charge_id":"ch_1","amount":5000}`

	t.Run("yes", func(t *testing.T) {
		f := newStdioFixture(t, askInClient)
		f.send(modernCall(1, "payments.refund", big, formCaps, ""))
		msg, state := question(t, f.recv())
		if !strings.Contains(msg, "payments.refund needs your approval") || !strings.Contains(msg, `"amount":5000`) {
			t.Errorf("question = %q", msg)
		}
		if strings.Contains(f.received(), "payments.refund") {
			t.Fatal("the call reached the server before anyone answered")
		}
		f.send(modernCall(2, "payments.refund", big, formCaps, answer(state, "accept", true)))
		if got := f.recv(); !strings.Contains(got, `"id":2`) || !strings.Contains(got, "ran tools/call payments.refund") {
			t.Fatalf("after yes: %s", got)
		}
		got := f.received()
		if strings.Contains(got, "requestState") || strings.Contains(got, askKey) {
			t.Errorf("our question's state reached the server:\n%s", got)
		}
		f.toWrapper.Close()
		<-f.done
		st, _ := store.OpenFile(f.stateDir, store.FileOptions{ReadOnly: true})
		entries, _ := st.ListAudit(context.Background(), audit.Filter{})
		found := false
		for _, e := range entries {
			found = found || (e.Outcome == audit.OutcomeApproved && e.Detail == "decided by local:ada via the MCP client")
		}
		if !found {
			t.Errorf("no approval made in the client in the audit log: %+v", entries)
		}
	})

	t.Run("no", func(t *testing.T) {
		f := newStdioFixture(t, askInClient)
		f.send(modernCall(1, "payments.refund", big, formCaps, ""))
		_, state := question(t, f.recv())
		f.send(modernCall(2, "payments.refund", big, formCaps, answer(state, "decline", false)))
		if got := f.recv(); !strings.Contains(got, "Rejected: the user declined") {
			t.Errorf("after no: %s", got)
		}
		f.send(modernCall(3, "payments.refund", big, formCaps, answer(state, "accept", false)))
		if got := f.recv(); !strings.Contains(got, "Rejected") {
			t.Errorf("accept with approve false: %s", got)
		}
		if strings.Contains(f.received(), "payments.refund") {
			t.Error("a declined call reached the server")
		}
	})

	t.Run("dismissed", func(t *testing.T) {
		f := newStdioFixture(t, askInClient)
		f.send(modernCall(1, "payments.refund", big, formCaps, ""))
		_, state := question(t, f.recv())
		f.send(modernCall(2, "payments.refund", big, formCaps, answer(state, "cancel", false)))
		// Not asked again straight away: the person said they don't want to choose now.
		if got := f.recv(); !strings.Contains(got, "Approval pending") || !strings.Contains(got, "consequenced -approve") {
			t.Errorf("after cancel: %s", got)
		}
	})

	t.Run("a forged or misused answer approves nothing", func(t *testing.T) {
		f := newStdioFixture(t, askInClient)
		f.send(modernCall(1, "payments.refund", big, formCaps, ""))
		_, state := question(t, f.recv())
		forged := state[:len(state)-2] + map[bool]string{true: "AA", false: "BB"}[!strings.HasSuffix(state, "AA")]
		for i, extra := range []string{
			answer("made-up", "accept", true),
			answer(forged, "accept", true),
			`"inputResponses":{"` + askKey + `":{"action":"accept","content":{"approve":true}}}`, // no state at all
		} {
			f.send(modernCall(10+i, "payments.refund", big, formCaps, extra))
			question(t, f.recv()) // asked again; nothing decided
		}
		// The real state, sent with other arguments, approves nothing either:
		// not the call it came with, nor the one it was asked about.
		f.send(modernCall(20, "payments.refund", `{"charge_id":"ch_1","amount":9000}`, formCaps, answer(state, "accept", true)))
		question(t, f.recv())
		f.send(modernCall(21, "payments.refund", big, formCaps, ""))
		question(t, f.recv())
		if strings.Contains(f.received(), "payments.refund") {
			t.Errorf("a call got through:\n%s", f.received())
		}
	})

	t.Run("a client that can't show forms", func(t *testing.T) {
		f := newStdioFixture(t, askInClient)
		for i, caps := range []string{`{}`, `{"elicitation":{"url":{}}}`} {
			f.send(modernCall(1+i, "payments.refund", big, caps, ""))
			if got := f.recv(); !strings.Contains(got, "Approval pending") {
				t.Errorf("caps %s: %s", caps, got)
			}
		}
	})

	t.Run("off unless asked for", func(t *testing.T) {
		f := newStdioFixture(t)
		f.send(modernCall(1, "payments.refund", big, formCaps, ""))
		if got := f.recv(); !strings.Contains(got, "Approval pending") {
			t.Errorf("got %s", got)
		}
	})

	t.Run("the server's own input passes through", func(t *testing.T) {
		f := newStdioFixture(t, askInClient)
		f.send(modernCall(1, "notes.read", `{}`, formCaps, `"requestState":"servers-own-state","inputResponses":{"login":{"action":"accept","content":{"name":"ada"}}}`))
		f.recv()
		if got := f.received(); !strings.Contains(got, `"requestState":"servers-own-state"`) || !strings.Contains(got, `"login"`) {
			t.Errorf("the server's own state was changed:\n%s", got)
		}
	})
}

func TestAskState(t *testing.T) {
	key, other := newAskKey(), newAskKey()
	now := time.Now()
	c := askClaims{ApprovalID: "apr_1", AgentID: "a", Tool: "t", ParamsHash: "sha256:x", Expires: now.Add(time.Minute).Unix()}
	state := signState(key, c)
	if got, ok := openState(key, state); !ok || got != c || !got.live(now) {
		t.Errorf("own state: %+v %v", got, ok)
	}
	if _, ok := openState(other, state); ok {
		t.Error("a state signed with another key was accepted")
	}
	body, sig, _ := strings.Cut(state, ".")
	tampered := strings.Replace(body, "Y", "Z", 1) + "." + sig
	if _, ok := openState(key, tampered); ok && tampered != state {
		t.Error("a changed state was accepted")
	}
	for _, bad := range []string{"", "x", "a.b", ".", state + "x"} {
		if _, ok := openState(key, bad); ok {
			t.Errorf("%q was accepted", bad)
		}
	}
	if c.live(now.Add(2 * time.Minute)) {
		t.Error("an expired state is live")
	}
}

func TestClientCanAsk(t *testing.T) {
	for caps, want := range map[string]bool{
		`{"elicitation":{}}`:                   true, // an empty elicitation means form
		`{"elicitation":{"form":{}}}`:          true,
		`{"elicitation":{"form":{},"url":{}}}`: true,
		`{"elicitation":{"url":{}}}`:           false,
		`{}`:                                   false,
		`{"sampling":{}}`:                      false,
	} {
		msg, rerr := parseMessage([]byte(modernCall(1, "x", `{}`, caps, "")))
		if rerr != nil {
			t.Fatal(rerr)
		}
		if got := clientCanAsk(msg); got != want {
			t.Errorf("%s: %v, want %v", caps, got, want)
		}
	}
}

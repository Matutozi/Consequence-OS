package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/gate"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// Asking through the client. With StdioOptions.AskInClient, a held call
// from a client that can show forms is answered the 2026-07-28 way
// (multi round-trip requests): a result with resultType "input_required"
// that asks the person "approve this call?" and carries a requestState.
// The client shows the question, then sends the same call again with the
// answer in params.inputResponses and the state in params.requestState.
// A yes approves the call, as consequenced -approve would, and the retry
// goes through.
//
// The requestState is signed with a key that exists only in this process,
// and names the approval, agent, tool and argument hash, with an expiry.
// An answer without it, or with one that was changed or belongs to other
// arguments, approves nothing.
//
// It is opt-in because it trusts the client: a client that shows the
// question to a person is as good as the terminal, but some agent
// frameworks let the model answer such questions, and then the agent
// would approve its own calls. The audit log records these decisions as
// made "via the MCP client".

// askKey is our key in inputRequests and inputResponses.
const askKey = "consequenceos_approval"

// askStateTTL is how long the person has to answer.
const askStateTTL = 15 * time.Minute

// askClaims is what a requestState vouches for.
type askClaims struct {
	ApprovalID string `json:"approval_id"`
	AgentID    string `json:"agent_id"`
	Tool       string `json:"tool"`
	ParamsHash string `json:"params_hash"`
	Expires    int64  `json:"exp"` // Unix seconds
}

func newAskKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err) // crypto/rand doesn't fail on supported systems
	}
	return key
}

func signState(key []byte, c askClaims) string {
	body, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// openState returns the claims of a requestState we signed, or ok=false
// for anything else: another server's state, or a changed one. It doesn't
// check the expiry; see askClaims.live.
func openState(key []byte, state string) (askClaims, bool) {
	body64, sig64, found := strings.Cut(state, ".")
	if !found {
		return askClaims{}, false
	}
	body, err1 := base64.RawURLEncoding.DecodeString(body64)
	sig, err2 := base64.RawURLEncoding.DecodeString(sig64)
	if err1 != nil || err2 != nil {
		return askClaims{}, false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return askClaims{}, false
	}
	var c askClaims
	if json.Unmarshal(body, &c) != nil {
		return askClaims{}, false
	}
	return c, true
}

// live reports whether the claims haven't expired.
func (c askClaims) live(now time.Time) bool { return now.Unix() <= c.Expires }

// clientCanAsk reports whether the request says its client shows forms:
// _meta's client capabilities hold elicitation, either empty (which means
// form) or with form.
func clientCanAsk(msg message) bool {
	var meta map[string]json.RawMessage
	if json.Unmarshal(msg.params["_meta"], &meta) != nil {
		return false
	}
	var caps struct {
		Elicitation *struct {
			Form *json.RawMessage `json:"form"`
			URL  *json.RawMessage `json:"url"`
		} `json:"elicitation"`
	}
	if json.Unmarshal(meta[metaClientCapabilities], &caps) != nil || caps.Elicitation == nil {
		return false
	}
	e := caps.Elicitation
	return e.Form != nil || e.URL == nil // {} means form; only url means no forms
}

// clientAnswer is what the retry says about our question.
type clientAnswer int

const (
	noAnswer clientAnswer = iota // not a retry of our question, or not one we can trust
	answeredYes
	answeredNo
	dismissed // the person closed the question without choosing
)

// readAnswer finds our question's answer in a retried call. It checks the
// signed state against this call before trusting anything in it.
func (s *stdio) readAnswer(msg message, call toolCall, now time.Time) (clientAnswer, string) {
	var state string
	if json.Unmarshal(msg.params["requestState"], &state) != nil || state == "" {
		return noAnswer, ""
	}
	claims, ok := openState(s.askKey, state)
	if !ok || !claims.live(now) {
		return noAnswer, ""
	}
	hash, err := verify.ParamsHash(call.rawArgs)
	if err != nil || claims.AgentID != s.opts.AgentID || claims.Tool != call.name || claims.ParamsHash != hash {
		return noAnswer, "" // a state for some other call
	}
	var responses map[string]struct {
		Action  string         `json:"action"`
		Content map[string]any `json:"content"`
	}
	if json.Unmarshal(msg.params["inputResponses"], &responses) != nil {
		return dismissed, claims.ApprovalID
	}
	r, ok := responses[askKey]
	switch {
	case !ok || r.Action == "cancel":
		return dismissed, claims.ApprovalID
	case r.Action == "accept" && r.Content["approve"] == true:
		return answeredYes, claims.ApprovalID
	case r.Action == "accept" || r.Action == "decline":
		return answeredNo, claims.ApprovalID
	}
	return dismissed, claims.ApprovalID
}

// applyAnswer decides the approval a retry answers, before the gate looks
// at the call. It returns whether the person dismissed the question, so
// the call isn't asked about again straight away.
func (s *stdio) applyAnswer(ctx context.Context, approvals *approval.Service, msg message, call toolCall) (dismissedIt bool) {
	if !s.opts.AskInClient {
		return false
	}
	answer, id := s.readAnswer(msg, call, time.Now())
	switch answer {
	case answeredYes, answeredNo:
		by := s.opts.LocalUser + " via the MCP client"
		if _, err := approvals.DecideLocally(ctx, id, by, answer == answeredYes); err != nil && !errors.Is(err, approval.ErrNotPending) {
			s.opts.Log.Error("stdio: the answer from the client couldn't be recorded", "approval_id", id, "err", err)
		}
	case dismissed:
		return true
	}
	return false
}

// askInClient answers a held call with a question for the person, if the
// options and the client allow it. It reports whether it did.
func (s *stdio) askInClient(msg message, call toolCall, res *gate.Result) bool {
	if !s.opts.AskInClient || !clientCanAsk(msg) {
		return false
	}
	a := res.Approval
	state := signState(s.askKey, askClaims{
		ApprovalID: a.ID, AgentID: s.opts.AgentID, Tool: call.name, ParamsHash: res.Entry.ParamsHash,
		Expires: time.Now().Add(askStateTTL).Unix(),
	})
	args := string(a.Arguments)
	if len(args) > 500 {
		args = args[:500] + "…"
	}
	question := fmt.Sprintf("ConsequenceOS: %s needs your approval (policy rule %q, consequence score %d of 100).", call.what(), res.Decision.Rule, a.Score)
	for _, r := range a.Reasons {
		question += " " + r
	}
	if res.ToolChanged {
		question += fmt.Sprintf(" The server changed what %s says it does since it was accepted, so check the call with that in mind.", call.name)
	}
	if args != "" && args != "{}" {
		question += " Arguments: " + args
	}
	s.client.writeJSON(map[string]any{"jsonrpc": "2.0", "id": msg.id, "result": map[string]any{
		"resultType": "input_required",
		"inputRequests": map[string]any{askKey: map[string]any{
			"method": "elicitation/create",
			"params": map[string]any{
				"mode":    "form",
				"message": question,
				"requestedSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"approve": map[string]any{"type": "boolean", "title": "Approve this call", "default": false},
					},
					"required": []string{"approve"},
				},
			},
		}},
		"requestState": state,
	}})
	return true
}

// withoutOurInput removes our answer and state from a retried call, so the
// server sees only what is meant for it: its own inputResponses, if any,
// and its own requestState.
func withoutOurInput(line []byte, ours bool) ([]byte, error) {
	if !ours {
		return line, nil
	}
	var top, params map[string]json.RawMessage
	if err := json.Unmarshal(line, &top); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(top["params"], &params); err != nil {
		return nil, err
	}
	delete(params, "requestState")
	var responses map[string]json.RawMessage
	if json.Unmarshal(params["inputResponses"], &responses) == nil {
		delete(responses, askKey)
		if len(responses) == 0 {
			delete(params, "inputResponses")
		} else {
			raw, err := marshalRaw(responses)
			if err != nil {
				return nil, err
			}
			params["inputResponses"] = raw
		}
	}
	raw, err := marshalRaw(params)
	if err != nil {
		return nil, err
	}
	top["params"] = raw
	return marshalRaw(top)
}

// carriesOurState reports whether a call's requestState is one we signed,
// expired or not: the server never issued it, so it must never see it.
func (s *stdio) carriesOurState(msg message) bool {
	var state string
	if json.Unmarshal(msg.params["requestState"], &state) != nil {
		return false
	}
	_, ok := openState(s.askKey, state)
	return ok
}

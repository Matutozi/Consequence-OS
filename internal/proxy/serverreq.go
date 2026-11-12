package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/gate"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// During a call, the server can ask the client for things: elicitation
// asks the user for input, sampling asks the client's model to write a
// message, roots asks which folders the client may use. A compromised
// server could use elicitation to ask the user for a password. So each
// such request goes past the policy, under the name server:elicitation,
// server:sampling, server:roots, or server: and the method, with its
// params as the arguments. Unlisted, they count as reads, so by default
// they're allowed, as before, and audited.
//
// A server asks in one of two ways:
//   - as a JSON-RPC request to the client, in an SSE stream or on a stdio
//     line (protocol versions before 2026-07-28). A refused request is
//     dropped, and the server is answered so it doesn't wait: an
//     elicitation is declined, anything else gets an error;
//   - as an input_required result with inputRequests (2026-07-28), which
//     the client answers by sending the call again. If any is refused,
//     the whole result is replaced with a refusal the agent can read.
//
// Pings and notifications pass: they ask nothing of the user.

// serverRequestName is the name rules match a server's request by.
func serverRequestName(method string) string {
	switch method {
	case "elicitation/create":
		return policy.ServerPrefix + "elicitation"
	case "sampling/createMessage":
		return policy.ServerPrefix + "sampling"
	case "roots/list":
		return policy.ServerPrefix + "roots"
	}
	return policy.ServerPrefix + method
}

// serverCheck checks the server's requests for one agent.
type serverCheck struct {
	// open gives the gate to decide with, and the function that closes it.
	open             func(ctx context.Context) (*gate.Gate, func(), error)
	agentID, ownerID string
	// reservedKey is an inputRequests key only ConsequenceOS may use (the
	// stdio wrapper's own question), or empty.
	reservedKey string
	log         *slog.Logger
}

// message checks one message from the server on its way to the client.
// out is the message to pass on, unless keep is false: then it's dropped,
// and answer, when set, is what to send the server for the request that
// was. method gives the method of the client's request a response
// answers, by its ID, or "" when it isn't known.
func (c serverCheck) message(ctx context.Context, msg []byte, method func(id json.RawMessage) string) (out []byte, keep bool, answer []byte) {
	if len(bytes.TrimSpace(msg)) == 0 {
		return msg, true, nil // an SSE event with no data, such as one that primes reconnection
	}
	var top map[string]json.RawMessage
	// Only JSON every parser reads the same way: otherwise a request one
	// client's lenient parser sees could pass here unseen.
	if _, err := verify.Canonicalize(msg); err != nil || json.Unmarshal(msg, &top) != nil {
		c.log.Error("dropped a message from the server that isn't strict JSON", "err", err)
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method *string         `json:"method"`
		}
		if json.Unmarshal(msg, &m) == nil && m.Method == nil && len(m.ID) > 0 && string(m.ID) != "null" {
			// An answer the client is waiting for: tell it, rather than let it wait.
			out, _ = marshalRaw(errorResponse(m.ID, codeInternalError, "the server's answer couldn't be read unambiguously, so ConsequenceOS didn't pass it on"))
			return out, true, nil
		}
		return nil, false, nil
	}
	id := top["id"]
	hasID := len(id) > 0 && string(id) != "null"
	if rawMethod, isRequest := top["method"]; isRequest {
		var m string
		if json.Unmarshal(rawMethod, &m) != nil || !hasID || m == "ping" {
			return msg, true, nil // a notification or a ping: nothing asked of the user
		}
		why := c.decide(ctx, m, top["params"])
		if why == "" {
			return msg, true, nil
		}
		c.log.Warn("refused a request from the server", "method", m, "why", why)
		return nil, false, serverAnswer(id, m, why)
	}
	result, ok := top["result"]
	if !ok {
		return msg, true, nil
	}
	var r struct {
		ResultType    string                     `json:"resultType"`
		InputRequests map[string]json.RawMessage `json:"inputRequests"`
	}
	if json.Unmarshal(result, &r) != nil || r.ResultType != "input_required" {
		return msg, true, nil
	}
	keys := make([]string, 0, len(r.InputRequests))
	for k := range r.InputRequests {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	why := ""
	if len(keys) == 0 {
		why = "it asked for input without saying for what"
	}
	for _, k := range keys {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		switch {
		case c.reservedKey != "" && strings.EqualFold(k, c.reservedKey):
			why = "it used ConsequenceOS's own input key, " + k
		case json.Unmarshal(r.InputRequests[k], &req) != nil || req.Method == "":
			why = "input request " + k + " names no method"
		default:
			why = c.decide(ctx, req.Method, req.Params)
		}
		if why != "" {
			break
		}
	}
	if why == "" {
		return msg, true, nil
	}
	c.log.Warn("refused a server's input request", "why", why)
	text := "Refused by ConsequenceOS: " + why + ". Do not retry this call."
	var refusal map[string]any
	if method != nil && method(id) == methodToolsCall {
		refusal = toolErrorResult(id, true, text)
	} else {
		refusal = errorResponse(id, codeRefused, text)
	}
	out, _ = marshalRaw(refusal)
	return out, true, nil
}

// decide runs one request from the server past the gate. It returns ""
// when the client may see it, and why not otherwise, as a clause:
// "the server asked to ask the user for input, and policy rule ... ".
func (c serverCheck) decide(ctx context.Context, method string, params json.RawMessage) string {
	name := serverRequestName(method)
	asked := "the server asked to " + approval.ServerAsk(strings.TrimPrefix(name, policy.ServerPrefix))
	var args map[string]any
	if len(params) > 0 && string(params) != "null" {
		if err := json.Unmarshal(params, &args); err != nil {
			return asked + ", with params that aren't an object"
		}
		if err := verify.CheckUnambiguous(params); err != nil {
			return asked + ", with params whose names differ only in letter case"
		}
	}
	g, closeGate, err := c.open(ctx)
	if err != nil {
		c.log.Error("the policy's state can't be opened to check a server request", "err", err)
		return asked + ", and ConsequenceOS couldn't check it just now"
	}
	defer closeGate()
	res, err := g.Decide(ctx, gate.Request{AgentID: c.agentID, OwnerID: c.ownerID, Name: name, RawArgs: params, Args: args})
	if err != nil {
		var gerr *gate.Error
		if errors.As(err, &gerr) {
			return asked + ", and it couldn't be checked: " + gerr.What
		}
		return asked + ", and it couldn't be checked"
	}
	defer res.Release()
	switch res.Verdict {
	case gate.Allowed, gate.AskUser: // AskUser: the client shows it to the person anyway
		if err := res.Admit(ctx, ""); err != nil {
			return asked + ", and it couldn't be recorded"
		}
		return ""
	case gate.Denied:
		return fmt.Sprintf("%s, and policy rule %q does not allow that", asked, res.Decision.Rule)
	case gate.Held:
		return fmt.Sprintf("%s, which needs a person's approval first (policy rule %q, approval %s); once it's approved, the same request goes through once",
			asked, res.Decision.Rule, res.Approval.ID)
	case gate.Declined:
		return fmt.Sprintf("%s, and a person declined that (approval %s)", asked, res.Approval.ID)
	case gate.TooManyPending:
		return asked + ", and too many requests are already waiting for approval"
	case gate.Invalid:
		return asked + ", and " + res.Reason
	}
	return asked + ", and ConsequenceOS couldn't decide it"
}

// serverAnswer is what the server gets for a request that was refused, so
// it doesn't wait: an elicitation is declined, as a user would decline
// it; anything else gets an error.
func serverAnswer(id json.RawMessage, method, why string) []byte {
	var answer map[string]any
	if method == "elicitation/create" {
		answer = map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"action": "decline"}}
	} else {
		// -1 is what the spec has clients use when the user rejects a request.
		answer = map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -1, "message": "Refused by ConsequenceOS: " + why}}
	}
	out, _ := marshalRaw(answer)
	return out
}

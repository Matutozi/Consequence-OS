package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// MCP and JSON-RPC names this file relies on, per the 2026-07-28 spec.
const (
	headerProtocolVersion = "MCP-Protocol-Version"
	headerMethod          = "Mcp-Method"
	headerName            = "Mcp-Name"
	headerReceipt         = "X-Consequence-Receipt"

	metaProtocolVersion = "io.modelcontextprotocol/protocolVersion"

	methodToolsCall     = "tools/call"
	methodResourcesRead = "resources/read"
	methodPromptsGet    = "prompts/get"

	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeInvalidParams  = -32602
	codeInternalError  = -32603
	codeHeaderMismatch = -32020
	// codeRefused is ours, for a read the policy blocked or is holding.
	// Tool calls are refused with a tool result instead; see refuse.
	codeRefused = -32030
)

// rpcError is a JSON-RPC error plus the HTTP status to send it with.
type rpcError struct {
	status  int
	code    int
	message string
}

func (e *rpcError) Error() string { return e.message }

// message is the part of a JSON-RPC message the proxy looks at. We decode
// into maps rather than structs on purpose: Go's struct decoding matches keys
// case-insensitively, so {"Name": "a", "name": "b"} could be read differently
// by us and by the upstream server. Maps keep keys exactly as sent.
type message struct {
	id     json.RawMessage // nil when absent (a notification)
	method string
	params map[string]json.RawMessage
}

// parseMessage validates one incoming JSON-RPC message. It rejects anything
// that could make the proxy and the upstream server disagree about what the
// message says: batches, duplicate keys, invalid UTF-8.
func parseMessage(body []byte) (message, *rpcError) {
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && trimmed[0] == '[' {
		// A batch could hide a tools/call from policy, and the current spec
		// allows only one message per request anyway.
		return message{}, &rpcError{http.StatusBadRequest, codeInvalidRequest, "batch requests are not supported"}
	}
	if err := verify.CheckUnambiguous(body); err != nil {
		switch {
		case errors.Is(err, verify.ErrDuplicateKey):
			return message{}, &rpcError{http.StatusBadRequest, codeInvalidRequest, "duplicate keys are not allowed in a request"}
		case errors.Is(err, verify.ErrCaseVariantKeys):
			return message{}, &rpcError{http.StatusBadRequest, codeInvalidRequest, "keys that differ only in letter case are not allowed"}
		}
		return message{}, &rpcError{http.StatusBadRequest, codeParseError, "parse error: body is not valid JSON"}
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return message{}, &rpcError{http.StatusBadRequest, codeInvalidRequest, "request must be a JSON object"}
	}
	var msg message
	if raw, ok := top["method"]; ok {
		if err := json.Unmarshal(raw, &msg.method); err != nil {
			return message{}, &rpcError{http.StatusBadRequest, codeInvalidRequest, "method must be a string"}
		}
	}
	msg.id = top["id"]
	if raw, ok := top["params"]; ok && gated(msg.method) {
		if err := json.Unmarshal(raw, &msg.params); err != nil {
			return message{}, &rpcError{http.StatusBadRequest, codeInvalidParams, msg.method + " params must be an object"}
		}
	}
	return msg, nil
}

// toolCall is a parsed gated request: a tools/call, or a resources/read or
// prompts/get, which the policy sees as a call named "resource:<uri>" or
// "prompt:<name>". See reads.go.
type toolCall struct {
	method  string
	name    string          // the name the policy matches
	target  string          // what Mcp-Name must equal: the tool name, URI or prompt name
	rawArgs json.RawMessage // exactly as sent, for hashing
	args    map[string]any  // decoded, for policy
	modern  bool            // carries 2026-07-28 per-request _meta
}

func parseToolCall(msg message) (toolCall, *rpcError) {
	var call toolCall
	if err := json.Unmarshal(msg.params["name"], &call.name); err != nil || call.name == "" {
		return toolCall{}, &rpcError{http.StatusBadRequest, codeInvalidParams, "tools/call needs params.name"}
	}
	call.target = call.name
	if policy.IsRead(call.name) {
		// Otherwise a tool named "resource:x" would be judged by the rules
		// written for reading resources.
		return call, &rpcError{http.StatusBadRequest, codeInvalidParams, "tool names may not start with resource: or prompt:"}
	}
	call.rawArgs = msg.params["arguments"]
	if len(call.rawArgs) > 0 && string(call.rawArgs) != "null" {
		if err := json.Unmarshal(call.rawArgs, &call.args); err != nil {
			return toolCall{}, &rpcError{http.StatusBadRequest, codeInvalidParams, "tools/call arguments must be an object"}
		}
	}
	return call, nil
}

// checkHeaders makes sure the routing headers, when sent, agree with the
// body. Otherwise a gateway routing on headers and the server reading the
// body could act on different tools or resources. Mcp-Name carries the
// tool name, the resource URI or the prompt name.
func checkHeaders(h http.Header, msg message, call *toolCall) *rpcError {
	if got := h.Get(headerMethod); got != "" && got != msg.method {
		return &rpcError{http.StatusBadRequest, codeHeaderMismatch, "Header mismatch: " + headerMethod}
	}
	if call != nil {
		if got := h.Get(headerName); got != "" && got != call.target {
			return &rpcError{http.StatusBadRequest, codeHeaderMismatch, "Header mismatch: " + headerName}
		}
	}
	return nil
}

// injectReceipt returns body with the receipt set at
// params._meta.consequenceReceipt, replacing any value the agent put there.
// Only that one key changes; arguments keep their exact meaning (and hash).
func injectReceipt(body, receipt []byte) ([]byte, error) {
	var top, params, meta map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(top["params"], &params); err != nil {
		return nil, err
	}
	if raw, ok := params["_meta"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, fmt.Errorf("params._meta must be an object")
		}
	}
	if meta == nil {
		meta = map[string]json.RawMessage{}
	}
	meta[verify.MetaKey] = receipt

	var err error
	if params["_meta"], err = marshalRaw(meta); err != nil {
		return nil, err
	}
	if top["params"], err = marshalRaw(params); err != nil {
		return nil, err
	}
	return marshalRaw(top)
}

// marshalRaw encodes without Go's default HTML escaping (which would turn
// "<" into "\u003c"), so string values reach the tool exactly as sent.
func marshalRaw(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// refuse answers a call that won't be forwarded. A tool call gets a tool
// result with isError, which the agent reads and can react to. Reads have no
// such result, so they get a JSON-RPC error carrying the same sentence.
func refuse(w http.ResponseWriter, msg message, call toolCall, text string) {
	if call.isTool() {
		writeJSON(w, http.StatusOK, toolErrorResult(msg.id, call.modern, text))
		return
	}
	writeJSON(w, http.StatusOK, errorResponse(msg.id, codeRefused, text))
}

// toolErrorResult builds a tools/call result with isError true. A result,
// rather than a JSON-RPC error, lets the agent read the message and react.
func toolErrorResult(id json.RawMessage, modern bool, text string) map[string]any {
	result := map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": true,
	}
	if modern {
		result["resultType"] = "complete"
	}
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
}

func errorResponse(id json.RawMessage, code int, msg string) map[string]any {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

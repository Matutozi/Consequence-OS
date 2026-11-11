package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"unicode"

	"github.com/matutozi/consequence-os/internal/policy"
)

// gated reports whether a method goes past the policy. Reading is the first
// half of most data leaks, so resource reads and prompt fetches are checked
// as well as tool calls. Everything else (initialize, tools/list, ...) passes.
func gated(method string) bool {
	switch method {
	case methodToolsCall, methodResourcesRead, methodPromptsGet:
		return true
	}
	return false
}

// parseCall parses any gated request into the call the policy sees.
func parseCall(msg message) (toolCall, *rpcError) {
	if len(msg.id) == 0 || string(msg.id) == "null" {
		// Some servers might act on a request sent as a notification, so we
		// never let one through without a decision and an id to answer.
		return toolCall{method: msg.method}, &rpcError{http.StatusBadRequest, codeInvalidRequest, msg.method + " needs an id"}
	}
	var call toolCall
	var rerr *rpcError
	switch msg.method {
	case methodResourcesRead:
		call, rerr = parseResourceRead(msg)
	case methodPromptsGet:
		call, rerr = parsePromptGet(msg)
	default:
		call, rerr = parseToolCall(msg)
	}
	call.method = msg.method
	if rerr != nil {
		return call, rerr
	}
	if hasControl(call.name) {
		// Also keeps NUL out, which the policy's glob matching relies on.
		return call, &rpcError{http.StatusBadRequest, codeInvalidParams, "names and URIs must not contain control characters"}
	}
	var meta map[string]json.RawMessage
	_ = json.Unmarshal(msg.params["_meta"], &meta) // absent or odd _meta just means a legacy client
	_, call.modern = meta[metaProtocolVersion]
	return call, nil
}

// parseResourceRead turns resources/read {uri} into "resource:<uri>".
func parseResourceRead(msg message) (toolCall, *rpcError) {
	var uri string
	if err := json.Unmarshal(msg.params["uri"], &uri); err != nil || uri == "" {
		return toolCall{}, &rpcError{http.StatusBadRequest, codeInvalidParams, "resources/read needs params.uri"}
	}
	if problem := checkResourceURI(uri); problem != "" {
		return toolCall{target: uri}, &rpcError{http.StatusBadRequest, codeInvalidParams, "resource URI refused: " + problem}
	}
	return toolCall{name: policy.ResourcePrefix + uri, target: uri}, nil
}

// parsePromptGet turns prompts/get {name, arguments} into "prompt:<name>",
// with the prompt's arguments available to conditions like a tool's.
func parsePromptGet(msg message) (toolCall, *rpcError) {
	var name string
	if err := json.Unmarshal(msg.params["name"], &name); err != nil || name == "" {
		return toolCall{}, &rpcError{http.StatusBadRequest, codeInvalidParams, "prompts/get needs params.name"}
	}
	call := toolCall{name: policy.PromptPrefix + name, target: name, rawArgs: msg.params["arguments"]}
	if len(call.rawArgs) > 0 && string(call.rawArgs) != "null" {
		if err := json.Unmarshal(call.rawArgs, &call.args); err != nil {
			return toolCall{target: name}, &rpcError{http.StatusBadRequest, codeInvalidParams, "prompts/get arguments must be an object"}
		}
	}
	return call, nil
}

// checkResourceURI refuses URIs that could name one resource while looking
// like another to a rule. Rules match the URI as text, so a deny rule for
// "resource:file:///etc/*" must not be dodged by "file:///tmp/../etc/passwd",
// "file:///%65tc/passwd" or "FILE:///etc/passwd". Rather than guess how the
// server will resolve such a URI, the proxy refuses it and asks for the
// plain form. It returns "" when the URI is fine, or what's wrong with it.
func checkResourceURI(uri string) string {
	for _, r := range uri {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "it must not contain spaces or control characters"
		}
	}
	if strings.ContainsRune(uri, '\\') {
		return "it must not contain backslashes; use / between path segments"
	}
	scheme, rest, ok := strings.Cut(uri, ":")
	if !ok || !validScheme(scheme) {
		return "it needs a scheme, such as file: or https:"
	}
	if strings.ToLower(scheme) != scheme {
		return "write the scheme in lower case"
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] != '%' {
			continue
		}
		if i+2 >= len(rest) || !isHex(rest[i+1]) || !isHex(rest[i+2]) {
			return "it has a % that isn't followed by two hex digits"
		}
		if c := unhex(rest[i+1])<<4 | unhex(rest[i+2]); isUnreserved(c) {
			return "write letters, digits and -._~ as themselves, not percent-encoded"
		}
	}
	path := rest
	if after, ok := strings.CutPrefix(rest, "//"); ok {
		authority, p, _ := cutAny(after, "/?#")
		if _, host, ok := strings.Cut(authority, "@"); ok {
			authority = host // user info may be case-sensitive; the host is not
		}
		if strings.ToLower(authority) != authority {
			return "write the host in lower case"
		}
		path = p
	}
	path, _, _ = cutAny(path, "?#")
	for seg := range strings.SplitSeq(path, "/") {
		if seg == "." || seg == ".." {
			return "it must not contain . or .. path segments; send the resolved URI"
		}
	}
	return ""
}

// cutAny splits s before the first byte that's in chars. The second half
// keeps that byte.
func cutAny(s, chars string) (before, after string, found bool) {
	if i := strings.IndexAny(s, chars); i >= 0 {
		return s[:i], s[i:], true
	}
	return s, "", false
}

// validScheme follows RFC 3986: a letter, then letters, digits, + - or .
func validScheme(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		letter := r < unicode.MaxASCII && unicode.IsLetter(r)
		if !letter && (i == 0 || !(r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.')) {
			return false
		}
	}
	return true
}

func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

// what describes a call for messages to the agent: the tool's name, or
// what is being read.
func (c toolCall) what() string {
	switch c.method {
	case methodResourcesRead:
		return "reading " + c.target
	case methodPromptsGet:
		return "getting the prompt " + c.target
	}
	return c.name
}

// isTool reports whether this is a tools/call, the only kind that gets a
// receipt: receipts are for actions, and receivers check only tools/call.
func (c toolCall) isTool() bool { return c.method == methodToolsCall }

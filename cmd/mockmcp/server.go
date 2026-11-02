package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/matutozi/consequence-os/pkg/verify"
)

// Protocol details below follow the MCP spec, revision 2026-07-28, with
// fallback to the legacy 2025-11-25 initialize flow for older clients.
const (
	versionModern = "2026-07-28"

	headerProtocolVersion = "MCP-Protocol-Version"
	headerMethod          = "Mcp-Method"
	headerName            = "Mcp-Name"
	headerReceipt         = "X-Consequence-Receipt"

	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	metaServerInfo         = "io.modelcontextprotocol/serverInfo"
)

// legacyVersions are the pre-2026 revisions we answer initialize for, newest first.
var legacyVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

// JSON-RPC and MCP error codes.
const (
	codeParseError         = -32700
	codeInvalidRequest     = -32600
	codeMethodNotFound     = -32601
	codeInvalidParams      = -32602
	codeHeaderMismatch     = -32020
	codeUnsupportedVersion = -32022
)

const maxBodyBytes = 1 << 20 // 1 MiB

var serverInfo = map[string]any{"name": "consequence-mockmcp", "version": "0.1.0"}

// message is any incoming JSON-RPC message. json.RawMessage keeps a field's
// raw bytes so we can tell "absent" (len 0) from "null".
type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// reply is what a method handler produces: an HTTP status plus a result or an error.
type reply struct {
	status int
	result map[string]any
	err    *rpcError
}

func ok(result map[string]any) reply { return reply{status: http.StatusOK, result: result} }

func fail(status, code int, msg string) reply {
	return reply{status: status, err: &rpcError{Code: code, Message: msg}}
}

// Server is a minimal MCP server over Streamable HTTP. It always answers
// with application/json and never opens SSE streams.
type Server struct {
	tools  []tool
	byName map[string]tool
	log    *slog.Logger
}

func NewServer(tools []tool, log *slog.Logger) *Server {
	byName := make(map[string]tool, len(tools))
	for _, t := range tools {
		byName[t.Name] = t
	}
	return &Server{tools: tools, byName: byName, log: log}
}

// ServeHTTP makes *Server satisfy http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// We offer no SSE stream and no sessions, so GET and DELETE get 405.
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !originAllowed(r.Header.Get("Origin")) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, nil, codeInvalidRequest, "body too large")
		return
	}
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && trimmed[0] == '[' {
		writeError(w, http.StatusBadRequest, nil, codeInvalidRequest, "batch requests are not supported")
		return
	}

	var msg message
	if err := json.Unmarshal(body, &msg); err != nil {
		writeError(w, http.StatusBadRequest, nil, codeParseError, "parse error")
		return
	}
	if msg.JSONRPC != "2.0" {
		writeError(w, http.StatusBadRequest, msg.ID, codeInvalidRequest, `jsonrpc must be "2.0"`)
		return
	}

	switch {
	case len(msg.ID) == 0 && msg.Method != "":
		// Notification (e.g. notifications/initialized): accept with no body.
		w.WriteHeader(http.StatusAccepted)
		return
	case msg.Method == "" && (len(msg.Result) > 0 || len(msg.Error) > 0):
		// A response from a legacy client to a server request; we never send any, so just accept.
		w.WriteHeader(http.StatusAccepted)
		return
	case msg.Method == "" || string(msg.ID) == "null":
		writeError(w, http.StatusBadRequest, msg.ID, codeInvalidRequest, "invalid request")
		return
	}

	rep := s.handle(r, msg)
	if rep.err != nil {
		writeError(w, rep.status, msg.ID, rep.err.Code, rep.err.Message, rep.err.Data)
		return
	}
	writeJSON(w, rep.status, response{JSONRPC: "2.0", ID: msg.ID, Result: rep.result})
}

// handle routes one request to its method and adds modern-era result fields.
func (s *Server) handle(r *http.Request, msg message) reply {
	if msg.Method == "initialize" {
		return s.initialize(msg.Params)
	}

	meta := readMeta(msg.Params)
	_, modern := meta[metaProtocolVersion]
	if modern {
		if rep, bad := checkModern(r, msg, meta); bad {
			return rep
		}
	} else if v := r.Header.Get(headerProtocolVersion); v != "" && !isLegacyVersion(v) {
		return fail(http.StatusBadRequest, codeInvalidRequest, "unsupported MCP-Protocol-Version "+v)
	}

	var rep reply
	switch msg.Method {
	case "server/discover":
		rep = ok(map[string]any{
			"supportedVersions": append([]string{versionModern}, legacyVersions...),
			"capabilities":      map[string]any{"tools": map[string]any{}},
		})
	case "ping":
		rep = ok(map[string]any{})
	case "tools/list":
		rep = s.listTools()
	case "tools/call":
		rep = s.callTool(r, msg.Params)
	default:
		status := http.StatusOK
		if modern {
			status = http.StatusNotFound // 2026-07-28: unknown method is HTTP 404
		}
		return fail(status, codeMethodNotFound, "method not found: "+msg.Method)
	}

	if modern && rep.err == nil {
		rep.result["resultType"] = "complete"
		rep.result["_meta"] = map[string]any{metaServerInfo: serverInfo}
	}
	return rep
}

// initialize answers the legacy (pre-2026) handshake. We don't assign a
// session ID; the spec makes sessions optional for the server.
func (s *Server) initialize(params json.RawMessage) reply {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p) // a missing or bad version just gets our default
	version := legacyVersions[0]
	if isLegacyVersion(p.ProtocolVersion) {
		version = p.ProtocolVersion // echo the client's version when we support it
	}
	return ok(map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      serverInfo,
	})
}

func (s *Server) listTools() reply {
	list := make([]map[string]any, 0, len(s.tools))
	for _, t := range s.tools {
		list = append(list, t.listing())
	}
	return ok(map[string]any{"tools": list})
}

func (s *Server) callTool(r *http.Request, params json.RawMessage) reply {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
		return fail(http.StatusBadRequest, codeInvalidParams, "tools/call needs params.name")
	}
	t, found := s.byName[p.Name]
	if !found {
		// Per the spec, an unknown tool is a protocol error, not isError.
		return fail(http.StatusOK, codeInvalidParams, "Unknown tool: "+p.Name)
	}

	text, isError := t.Call(p.Arguments)
	// Never log arguments; the receipt ID (when one was verified) is enough.
	receiptID := ""
	if rcpt, ok := verify.FromContext(r.Context()); ok {
		receiptID = rcpt.ReceiptID
	}
	s.log.Info("tools/call", "tool", p.Name, "is_error", isError,
		"receipt_present", r.Header.Get(headerReceipt) != "", "receipt_id", receiptID)
	return ok(map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	})
}

// checkModern applies the 2026-07-28 per-request checks. It returns bad=true
// with the error reply when the request must be rejected.
func checkModern(r *http.Request, msg message, meta map[string]json.RawMessage) (rep reply, bad bool) {
	var version string
	if err := json.Unmarshal(meta[metaProtocolVersion], &version); err != nil {
		return fail(http.StatusBadRequest, codeInvalidParams, metaProtocolVersion+" must be a string"), true
	}
	if version != versionModern {
		rep := fail(http.StatusBadRequest, codeUnsupportedVersion, "Unsupported protocol version")
		rep.err.Data = map[string]any{"supported": []string{versionModern}, "requested": version}
		return rep, true
	}
	if _, has := meta[metaClientCapabilities]; !has {
		return fail(http.StatusBadRequest, codeInvalidParams, "missing _meta "+metaClientCapabilities), true
	}

	if got := r.Header.Get(headerProtocolVersion); got != version {
		return fail(http.StatusBadRequest, codeHeaderMismatch, "Header mismatch: "+headerProtocolVersion), true
	}
	if got := r.Header.Get(headerMethod); got != msg.Method {
		return fail(http.StatusBadRequest, codeHeaderMismatch, "Header mismatch: "+headerMethod), true
	}
	if msg.Method == "tools/call" {
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(msg.Params, &p)
		if r.Header.Get(headerName) != p.Name {
			return fail(http.StatusBadRequest, codeHeaderMismatch, "Header mismatch: "+headerName), true
		}
	}
	return reply{}, false
}

func readMeta(params json.RawMessage) map[string]json.RawMessage {
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	_ = json.Unmarshal(params, &p) // absent or malformed params simply have no _meta
	return p.Meta
}

func isLegacyVersion(v string) bool {
	for _, lv := range legacyVersions {
		if v == lv {
			return true
		}
	}
	return false
}

// originAllowed guards against DNS rebinding: browsers send Origin, and only
// local pages may talk to the mock. Non-browser clients send no Origin.
func originAllowed(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func writeError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string, data ...any) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	e := &rpcError{Code: code, Message: msg}
	if len(data) > 0 {
		e.Data = data[0]
	}
	writeJSON(w, status, response{JSONRPC: "2.0", ID: id, Error: e})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // the client has gone if this fails; nothing useful to do
}

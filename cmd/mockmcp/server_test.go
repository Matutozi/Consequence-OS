package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// modernBody builds a 2026-07-28 style request with the required _meta.
func modernBody(id int, method string, params map[string]any) string {
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{
		metaProtocolVersion:    versionModern,
		metaClientCapabilities: map[string]any{},
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return string(b)
}

// modernHeaders returns the headers 2026-07-28 requires for a method.
func modernHeaders(method, name string) map[string]string {
	h := map[string]string{headerProtocolVersion: versionModern, headerMethod: method}
	if name != "" {
		h[headerName] = name
	}
	return h
}

func callParams(name string, args map[string]any) map[string]any {
	return map[string]any{"name": name, "arguments": args}
}

type decoded struct {
	Result map[string]any `json:"result"`
	Error  *rpcError      `json:"error"`
}

func TestServer(t *testing.T) {
	srv := NewServer(defaultTools(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	tests := []struct {
		name       string
		method     string // HTTP method; defaults to POST
		body       string
		headers    map[string]string
		wantStatus int
		wantCode   int                              // JSON-RPC error code, 0 for none
		check      func(*testing.T, map[string]any) // optional check of the result
	}{
		{name: "GET not allowed", method: http.MethodGet, wantStatus: 405},
		{name: "DELETE not allowed", method: http.MethodDelete, wantStatus: 405},
		{
			name: "foreign origin rejected", body: `{}`,
			headers: map[string]string{"Origin": "https://evil.example"}, wantStatus: 403,
		},
		{
			name: "local origin allowed", body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			headers: map[string]string{"Origin": "http://localhost:3000"}, wantStatus: 202,
		},
		{name: "parse error", body: `{not json`, wantStatus: 400, wantCode: codeParseError},
		{name: "batch rejected", body: `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, wantStatus: 400, wantCode: codeInvalidRequest},
		{name: "wrong jsonrpc version", body: `{"jsonrpc":"1.0","id":1,"method":"ping"}`, wantStatus: 400, wantCode: codeInvalidRequest},
		{name: "null id rejected", body: `{"jsonrpc":"2.0","id":null,"method":"ping"}`, wantStatus: 400, wantCode: codeInvalidRequest},
		{name: "notification accepted", body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`, wantStatus: 202},
		{name: "client response accepted", body: `{"jsonrpc":"2.0","id":7,"result":{}}`, wantStatus: 202},
		{
			name:       "legacy initialize echoes supported version",
			body:       `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
			wantStatus: 200,
			check: func(t *testing.T, r map[string]any) {
				if r["protocolVersion"] != "2025-06-18" {
					t.Errorf("protocolVersion = %v", r["protocolVersion"])
				}
				if r["serverInfo"] == nil || r["capabilities"] == nil {
					t.Errorf("missing serverInfo or capabilities: %v", r)
				}
			},
		},
		{
			name:       "legacy initialize with unknown version gets our latest legacy",
			body:       `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2020-01-01"}}`,
			wantStatus: 200,
			check: func(t *testing.T, r map[string]any) {
				if r["protocolVersion"] != legacyVersions[0] {
					t.Errorf("protocolVersion = %v", r["protocolVersion"])
				}
			},
		},
		{
			name:       "legacy tools/list",
			body:       `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
			headers:    map[string]string{headerProtocolVersion: "2025-11-25"},
			wantStatus: 200,
			check: func(t *testing.T, r map[string]any) {
				tools := r["tools"].([]any)
				if len(tools) != 2 {
					t.Fatalf("got %d tools", len(tools))
				}
				if _, has := r["resultType"]; has {
					t.Error("legacy result should not carry resultType")
				}
				if _, has := r["ttlMs"]; has {
					t.Error("legacy result should not carry ttlMs")
				}
			},
		},
		{
			name:       "legacy unsupported header version",
			body:       `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
			headers:    map[string]string{headerProtocolVersion: "1999-01-01"},
			wantStatus: 400, wantCode: codeInvalidRequest,
		},
		{name: "legacy unknown method", body: `{"jsonrpc":"2.0","id":3,"method":"nope"}`, wantStatus: 200, wantCode: codeMethodNotFound},
		{
			name: "modern server/discover", body: modernBody(1, "server/discover", nil),
			headers: modernHeaders("server/discover", ""), wantStatus: 200,
			check: func(t *testing.T, r map[string]any) {
				if r["resultType"] != "complete" || r["supportedVersions"] == nil {
					t.Errorf("bad discover result: %v", r)
				}
				if r["ttlMs"] != 0.0 || r["cacheScope"] != "private" {
					t.Errorf("discover needs ttlMs and cacheScope: %v", r)
				}
				meta := r["_meta"].(map[string]any)
				if meta[metaServerInfo] == nil {
					t.Error("missing serverInfo in _meta")
				}
			},
		},
		{
			name: "modern tools/list", body: modernBody(2, "tools/list", nil),
			headers: modernHeaders("tools/list", ""), wantStatus: 200,
			check: func(t *testing.T, r map[string]any) {
				first := r["tools"].([]any)[0].(map[string]any)
				if first["name"] != "notes.read" || first["inputSchema"] == nil {
					t.Errorf("unexpected first tool: %v", first)
				}
				if r["ttlMs"] != 0.0 || r["cacheScope"] != "private" {
					t.Errorf("tools/list needs ttlMs and cacheScope: %v", r)
				}
			},
		},
		{
			name: "modern missing version header", body: modernBody(2, "tools/list", nil),
			headers: map[string]string{headerMethod: "tools/list"}, wantStatus: 400, wantCode: codeHeaderMismatch,
		},
		{
			name: "modern Mcp-Method mismatch", body: modernBody(2, "tools/list", nil),
			headers: modernHeaders("ping", ""), wantStatus: 400, wantCode: codeHeaderMismatch,
		},
		{
			name:    "modern Mcp-Name mismatch",
			body:    modernBody(3, "tools/call", callParams("notes.read", map[string]any{"note_id": "welcome"})),
			headers: modernHeaders("tools/call", "payments.refund"), wantStatus: 400, wantCode: codeHeaderMismatch,
		},
		{
			name:       "modern unsupported version",
			body:       `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`,
			headers:    map[string]string{headerProtocolVersion: "1900-01-01", headerMethod: "ping"},
			wantStatus: 400, wantCode: codeUnsupportedVersion,
		},
		{
			name:       "modern missing client capabilities",
			body:       `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
			headers:    modernHeaders("ping", ""),
			wantStatus: 400, wantCode: codeInvalidParams,
		},
		{
			name: "modern unknown method is 404", body: modernBody(4, "nope", nil),
			headers: modernHeaders("nope", ""), wantStatus: 404, wantCode: codeMethodNotFound,
		},
		{
			name:    "refund succeeds",
			body:    modernBody(5, "tools/call", callParams("payments.refund", map[string]any{"charge_id": "ch_1", "amount": 5000})),
			headers: modernHeaders("tools/call", "payments.refund"), wantStatus: 200,
			check: wantText(false, "Refunded 5000.00 USD on charge ch_1"),
		},
		{
			name:    "refund with bad amount is a tool error",
			body:    modernBody(6, "tools/call", callParams("payments.refund", map[string]any{"charge_id": "ch_1", "amount": -1})),
			headers: modernHeaders("tools/call", "payments.refund"), wantStatus: 200,
			check: wantText(true, "amount must be a positive number"),
		},
		{
			name:    "notes.read succeeds",
			body:    modernBody(7, "tools/call", callParams("notes.read", map[string]any{"note_id": "refund-policy"})),
			headers: modernHeaders("tools/call", "notes.read"), wantStatus: 200,
			check: wantText(false, "Refunds over $50"),
		},
		{
			name:    "notes.read unknown note is a tool error",
			body:    modernBody(8, "tools/call", callParams("notes.read", map[string]any{"note_id": "missing"})),
			headers: modernHeaders("tools/call", "notes.read"), wantStatus: 200,
			check: wantText(true, "No note"),
		},
		{
			name:    "unknown tool is a protocol error",
			body:    modernBody(9, "tools/call", callParams("db.drop", nil)),
			headers: modernHeaders("tools/call", "db.drop"), wantStatus: 200, wantCode: codeInvalidParams,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			req := httptest.NewRequest(method, "/mcp", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			if rec.Code == 202 {
				if rec.Body.Len() != 0 {
					t.Errorf("202 must have an empty body, got %q", rec.Body)
				}
				return
			}
			if rec.Code == 405 || rec.Code == 403 {
				return
			}

			var got decoded
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("response is not JSON: %v; body: %s", err, rec.Body)
			}
			if tt.wantCode != 0 {
				if got.Error == nil || got.Error.Code != tt.wantCode {
					t.Fatalf("error = %+v, want code %d", got.Error, tt.wantCode)
				}
				return
			}
			if got.Error != nil {
				t.Fatalf("unexpected error: %+v", got.Error)
			}
			if tt.check != nil {
				tt.check(t, got.Result)
			}
		})
	}
}

// wantText checks a tools/call result's isError flag and first text block.
func wantText(isError bool, contains string) func(*testing.T, map[string]any) {
	return func(t *testing.T, r map[string]any) {
		if r["isError"] != isError {
			t.Errorf("isError = %v, want %v", r["isError"], isError)
		}
		content := r["content"].([]any)
		text := content[0].(map[string]any)["text"].(string)
		if !strings.Contains(text, contains) {
			t.Errorf("text = %q, want it to contain %q", text, contains)
		}
	}
}

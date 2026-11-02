package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
)

// CodeReceiptRejected is the JSON-RPC error code the middleware answers with.
// It sits outside JSON-RPC's reserved range (-32768 to -32000).
const CodeReceiptRejected = -31001

const maxBodyBytes = 4 << 20

// contextKey is unexported so no other package can collide with it.
type contextKey struct{}

// FromContext returns the receipt the middleware verified for this request.
func FromContext(ctx context.Context) (*Receipt, bool) {
	r, ok := ctx.Value(contextKey{}).(*Receipt)
	return r, ok
}

// Middleware protects an MCP server: every tools/call must carry a valid
// receipt for exactly that tool and those arguments, or it is refused with
// HTTP 403 before the handler runs. Other MCP messages pass through.
//
//	mux.Handle("/mcp", verify.Middleware(verify.NewClient("http://localhost:8080"), nil)(myServer))
func Middleware(v Verifier, log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
			if err != nil {
				reject(w, nil, ErrMalformed)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body)) // let the handler read it again

			if err := CheckUnambiguous(body); err != nil {
				if errors.Is(err, ErrDuplicateKey) || errors.Is(err, ErrCaseVariantKeys) {
					reject(w, nil, ErrMalformed) // could be read two ways: never let it reach a tool
					return
				}
				next.ServeHTTP(w, r) // not JSON at all: the server answers with a parse error
				return
			}
			call, isCall, err := parseCall(body)
			if !isCall {
				next.ServeHTTP(w, r)
				return
			}
			if err != nil {
				reject(w, call.id, err)
				return
			}
			receipt := []byte(r.Header.Get(HeaderName))
			if len(receipt) == 0 {
				receipt = call.metaReceipt
			}
			if len(receipt) == 0 {
				log.Warn("tools/call refused: no receipt", "tool", call.name)
				reject(w, call.id, ErrMissing)
				return
			}
			verified, err := v.Verify(r.Context(), receipt, call.name, call.arguments)
			if err != nil {
				log.Warn("tools/call refused", "tool", call.name, "reason", Reason(err))
				reject(w, call.id, err)
				return
			}
			log.Info("receipt verified", "tool", call.name, "receipt_id", verified.ReceiptID, "decision", verified.Decision)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, verified)))
		})
	}
}

type mcpCall struct {
	id          json.RawMessage
	name        string
	arguments   []byte
	metaReceipt []byte
}

// parseCall extracts what the middleware needs from an unambiguous body. It
// reads exact keys (maps, not structs: Go struct decoding ignores case), so it
// hashes exactly the arguments the tool will see. ok is false when the body
// is not a tools/call; err is set when it is one but has no tool name.
func parseCall(body []byte) (call mcpCall, ok bool, err error) {
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return mcpCall{}, false, nil
	}
	var method string
	if json.Unmarshal(top["method"], &method) != nil || method != "tools/call" {
		return mcpCall{}, false, nil
	}
	var params map[string]json.RawMessage
	_ = json.Unmarshal(top["params"], &params)
	var meta map[string]json.RawMessage
	_ = json.Unmarshal(params["_meta"], &meta)
	call = mcpCall{id: top["id"], arguments: params["arguments"], metaReceipt: meta[MetaKey]}
	if json.Unmarshal(params["name"], &call.name) != nil || call.name == "" {
		return mcpCall{}, true, ErrMalformed
	}
	return call, true, nil
}

func reject(w http.ResponseWriter, id json.RawMessage, err error) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]any{
			"code":    CodeReceiptRejected,
			"message": "ConsequenceOS receipt rejected: " + err.Error(),
			"data":    map[string]string{"reason": Reason(err)},
		},
	})
}

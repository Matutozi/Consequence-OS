package receipt

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/matutozi/consequence-os/pkg/verify"
)

// VerifyHandler serves POST /v1/receipts/verify. The answer is always 200
// with "valid" true or false for a well-formed request, so receivers have
// one thing to check; a broken request gets 400.
func VerifyHandler(c *Checker, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeJSON(w, http.StatusRequestEntityTooLarge, verify.VerifyResponse{Reason: "malformed", Message: "request too large"})
			return
		}
		var req verify.VerifyRequest
		if err := json.Unmarshal(body, &req); err != nil || len(req.Receipt) == 0 || req.Tool == "" {
			writeJSON(w, http.StatusBadRequest, verify.VerifyResponse{Reason: "malformed", Message: "send {receipt, tool, arguments}"})
			return
		}

		receipt := req.Receipt
		var s string
		if json.Unmarshal(receipt, &s) == nil { // accept the receipt as a JSON string too
			receipt = []byte(s)
		}
		args := req.Arguments
		if len(args) == 0 || string(args) == "null" {
			args = json.RawMessage("{}")
		}

		verified, err := c.Verify(r.Context(), receipt, req.Tool, args)
		if err != nil {
			reason := verify.Reason(err)
			if reason == "invalid" { // not a receipt problem, e.g. the store is down
				log.Error("receipt verification failed", "err", err)
				writeJSON(w, http.StatusServiceUnavailable, verify.VerifyResponse{Reason: "unavailable", Message: "could not verify right now"})
				return
			}
			log.Info("receipt rejected", "tool", req.Tool, "reason", reason)
			writeJSON(w, http.StatusOK, verify.VerifyResponse{Valid: false, Reason: reason, Message: err.Error()})
			return
		}
		log.Info("receipt verified", "receipt_id", verified.ReceiptID, "tool", verified.Action.Tool, "decision", verified.Decision)
		writeJSON(w, http.StatusOK, verify.VerifyResponse{Valid: true, Receipt: verified})
	})
}

// KeysHandler serves GET /.well-known/consequence-keys.
func KeysHandler(keys *Keys) http.Handler {
	jwks, _ := json.Marshal(keys.JWKS()) // public keys don't change while running
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(jwks)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

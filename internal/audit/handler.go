package audit

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// Handler serves GET /v1/audit. It requires the admin token as a Bearer token.
func Handler(store Lister, adminToken string, log *slog.Logger) http.Handler {
	// http.HandlerFunc turns a plain function into an http.Handler.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validBearer(r.Header.Get("Authorization"), adminToken) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="consequenceos-admin"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin token required"})
			return
		}
		filter, err := ParseFilter(r.URL.Query())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		entries, err := store.ListAudit(r.Context(), filter)
		if err != nil {
			log.Error("list audit entries", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read the audit log"})
			return
		}
		if entries == nil {
			entries = []Entry{} // encode as [] rather than null
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
	})
}

func validBearer(header, want string) bool {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || want == "" {
		return false
	}
	// ConstantTimeCompare takes the same time whether the first or last byte
	// differs, so the response time leaks nothing about the token.
	return subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

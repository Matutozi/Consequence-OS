package audit

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

// Handler serves GET /v1/audit. It requires the admin token as a Bearer token.
func Handler(store Lister, adminToken string, log *slog.Logger) http.Handler {
	// http.HandlerFunc turns a plain function into an http.Handler.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, adminToken) {
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

// VerifyHandler serves GET /v1/audit/verify: it checks the whole hash chain
// and answers with a ChainReport. It needs the admin token.
//
// With ?seq=N&hash=sha256:..., the place and hash of a head saved earlier,
// the log must also still contain that entry, as with consequenced
// -verify-audit -audit-head. An anchoring tool asks this before anchoring
// a newer head, so it never vouches for a log that was cut back or rebuilt.
//
// check checks the signed head of the anchor the log starts from after
// archiving, with the server's keys.
func VerifyHandler(w Walker, check HeadChecker, adminToken string, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !requireAdmin(rw, r, adminToken) {
			return
		}
		v := &ChainVerifier{CheckHead: check}
		if q := r.URL.Query(); q.Has("seq") || q.Has("hash") {
			seq, err := strconv.ParseInt(q.Get("seq"), 10, 64)
			hash := q.Get("hash")
			if err != nil || seq < 1 || !strings.HasPrefix(hash, "sha256:") || len(q["seq"]) > 1 || len(q["hash"]) > 1 {
				writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "seq and hash go together: the place (1 or more) and the sha256:... hash of an entry the log must still contain"})
				return
			}
			v.ExpectHead(seq, hash)
		}
		report, err := VerifyChainWith(r.Context(), w, v)
		if err != nil {
			log.Error("verify audit chain", "err", err)
			writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": "could not read the audit log"})
			return
		}
		if !report.Intact {
			log.Warn("audit chain broken", "broken_at", report.BrokenAt, "problem", report.Problem)
		}
		writeJSON(rw, http.StatusOK, report)
	})
}

// HeadSource gives the newest audit entry. The store implements it.
type HeadSource interface {
	LastAudit(ctx context.Context) (e Entry, ok bool, err error)
}

// HeadSigner signs "entry seq has hash" with the server's keys.
type HeadSigner func(seq int64, hash string) ([]byte, error)

// HeadHandler serves GET /v1/audit/head: the newest entry's place and hash,
// signed. Auditors save these; the log before a saved head can't then be
// rewritten unnoticed. It needs the admin token.
func HeadHandler(src HeadSource, sign HeadSigner, adminToken string, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !requireAdmin(rw, r, adminToken) {
			return
		}
		last, ok, err := src.LastAudit(r.Context())
		if err != nil {
			log.Error("read audit head", "err", err)
			writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": "could not read the audit log"})
			return
		}
		if !ok {
			// Every entry was archived: the chain ends at the anchor.
			if anchors, isSource := src.(AnchorSource); isSource {
				a, archived, err := anchors.AuditAnchor(r.Context())
				if err != nil {
					log.Error("read audit anchor", "err", err)
					writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": "could not read the audit log"})
					return
				}
				if archived {
					last, ok = Entry{Seq: a.Seq, Hash: a.Hash}, true
				}
			}
		}
		if !ok || last.Hash == "" {
			writeJSON(rw, http.StatusNotFound, map[string]string{"error": "the audit log has no chained entries yet"})
			return
		}
		signed, err := sign(last.Seq, last.Hash)
		if err != nil {
			log.Error("sign audit head", "err", err)
			writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": "could not sign the audit head"})
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write(signed)
	})
}

// requireAdmin answers 401 and returns false unless the request carries the admin token.
func requireAdmin(w http.ResponseWriter, r *http.Request, adminToken string) bool {
	if validBearer(r.Header.Get("Authorization"), adminToken) {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="consequenceos-admin"`)
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin token required"})
	return false
}

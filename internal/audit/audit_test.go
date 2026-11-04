package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/policy"
)

func TestParseFilter(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		want    Filter
		wantErr string
	}{
		{"empty", "", Filter{}, ""},
		{
			"everything",
			"agent=support-bot&tool=payments.refund&decision=ask&since=2026-11-02T10:00:00Z&until=2026-11-02T11:00:00Z&limit=5",
			Filter{
				AgentID: "support-bot", Tool: "payments.refund", Decision: policy.ActionAsk,
				Since: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC), Until: time.Date(2026, 11, 2, 11, 0, 0, 0, time.UTC), Limit: 5,
			},
			"",
		},
		{"bad decision", "decision=maybe", Filter{}, "decision must be"},
		{"bad since", "since=yesterday", Filter{}, "since"},
		{"bad until", "until=2026-11-02", Filter{}, "until"},
		{"bad limit", "limit=-3", Filter{}, "limit"},
		{"non-numeric limit", "limit=lots", Filter{}, "limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, _ := url.ParseQuery(tt.query)
			got, err := ParseFilter(q)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want { // structs with comparable fields can be compared with ==
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestEffectiveLimit(t *testing.T) {
	tests := []struct{ in, want int }{{0, DefaultLimit}, {-1, DefaultLimit}, {5, 5}, {MaxLimit + 1, MaxLimit}}
	for _, tt := range tests {
		if got := (Filter{Limit: tt.in}).EffectiveLimit(); got != tt.want {
			t.Errorf("EffectiveLimit(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

// fakeLister records the filter it was given and returns canned entries.
type fakeLister struct {
	got     Filter
	entries []Entry
	err     error
}

func (f *fakeLister) ListAudit(_ context.Context, filter Filter) ([]Entry, error) {
	f.got = filter
	return f.entries, f.err
}

func TestHandler(t *testing.T) {
	const token = "admin-secret"
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name       string
		auth       string
		query      string
		lister     *fakeLister
		wantStatus int
		wantBody   string
	}{
		{"no token", "", "", &fakeLister{}, 401, "admin token required"},
		{"wrong token", "Bearer nope", "", &fakeLister{}, 401, "admin token required"},
		{"wrong scheme", "Basic " + token, "", &fakeLister{}, 401, "admin token required"},
		{"bad filter", "Bearer " + token, "decision=maybe", &fakeLister{}, 400, "decision must be"},
		{"store fails", "Bearer " + token, "", &fakeLister{err: errors.New("disk on fire")}, 500, "could not read"},
		{"empty log is an empty list", "Bearer " + token, "", &fakeLister{}, 200, `"entries":[]`},
		{"lowercase bearer", "bearer " + token, "", &fakeLister{}, 200, `"entries":[]`},
		{"entries", "Bearer " + token, "tool=notes.read", &fakeLister{entries: []Entry{{ID: "aud_1", Tool: "notes.read", Outcome: OutcomeForwarded}}}, 200, `"id":"aud_1"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/audit?"+tt.query, nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			rec := httptest.NewRecorder()
			Handler(tt.lister, token, log).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.wantStatus, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body %s does not contain %s", rec.Body, tt.wantBody)
			}
			if !json.Valid(rec.Body.Bytes()) {
				t.Error("body is not valid JSON")
			}
		})
	}
}

func TestHandlerPassesFilter(t *testing.T) {
	l := &fakeLister{}
	req := httptest.NewRequest(http.MethodGet, "/v1/audit?agent=a&tool=t&decision=deny", nil)
	req.Header.Set("Authorization", "Bearer k")
	Handler(l, "k", slog.New(slog.NewTextHandler(io.Discard, nil))).ServeHTTP(httptest.NewRecorder(), req)
	want := Filter{AgentID: "a", Tool: "t", Decision: policy.ActionDeny}
	if l.got != want {
		t.Errorf("store got filter %+v, want %+v", l.got, want)
	}
}

type fakeHead struct {
	last Entry
	ok   bool
}

func (f fakeHead) LastAudit(context.Context) (Entry, bool, error) { return f.last, f.ok, nil }

func TestVerifyAndHeadHandlers(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	entries := chainOf(t, 3)
	// A copy with the middle entry removed. (append on entries[:1] would overwrite entries itself.)
	missing := append([]Entry{entries[0]}, entries[2:]...)
	sign := func(seq int64, hash string) ([]byte, error) {
		return []byte(fmt.Sprintf(`{"signed":%d,"hash":%q}`, seq, hash)), nil
	}
	tests := []struct {
		name       string
		handler    http.Handler
		token      string
		wantStatus int
		wantBody   string
	}{
		{"verify needs the token", VerifyHandler(walker(entries), "admin", log), "", 401, "admin token required"},
		{"verify intact", VerifyHandler(walker(entries), "admin", log), "admin", 200, `"intact":true`},
		{"verify broken", VerifyHandler(walker(missing), "admin", log), "admin", 200, `"broken_at":"aud_c"`},
		{"head needs the token", HeadHandler(fakeHead{entries[2], true}, sign, "admin", log), "wrong", 401, "admin token required"},
		{"head is signed", HeadHandler(fakeHead{entries[2], true}, sign, "admin", log), "admin", 200, `{"signed":3,"hash":"` + entries[2].Hash + `"}`},
		{"empty log has no head", HeadHandler(fakeHead{}, sign, "admin", log), "admin", 404, "no chained entries"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/audit/x", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rec := httptest.NewRecorder()
			tt.handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus || !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("got %d %s", rec.Code, rec.Body)
			}
		})
	}
}

// Package audit defines audit log entries, how to filter them, and the
// GET /v1/audit endpoint. Storage lives in internal/store.
package audit

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/matutozi/consequence-os/internal/policy"
)

// Outcome is what happened to a call after the policy decided.
type Outcome string

const (
	OutcomeForwarded Outcome = "forwarded" // sent on to the upstream tool server
	OutcomeBlocked   Outcome = "blocked"   // denied by policy
	OutcomeHeld      Outcome = "held"      // waiting for a human
	OutcomeRejected  Outcome = "rejected"  // malformed, never evaluated
	OutcomeApproved  Outcome = "approved"  // a human approved a held call
	OutcomeDeclined  Outcome = "declined"  // a human said no, or a retry of a declined call
)

// Entry is one line in the audit log. It never holds raw arguments, only
// their hash and a short summary.
type Entry struct {
	ID         string        `json:"id"`
	Time       time.Time     `json:"time"`
	AgentID    string        `json:"agent_id"`
	OwnerID    string        `json:"owner_id"`
	Tool       string        `json:"tool"`
	ParamsHash string        `json:"params_hash,omitempty"`
	Summary    string        `json:"summary,omitempty"`
	Level      policy.Level  `json:"level,omitempty"`
	Decision   policy.Action `json:"decision,omitempty"`
	Rule       string        `json:"rule,omitempty"`
	Outcome    Outcome       `json:"outcome"`
	ApprovalID string        `json:"approval_id,omitempty"`
	ReceiptID  string        `json:"receipt_id,omitempty"`
	Detail     string        `json:"detail,omitempty"`
}

// Filter selects entries. Zero values mean "any".
type Filter struct {
	AgentID  string
	Tool     string
	Decision policy.Action
	Since    time.Time // inclusive
	Until    time.Time // exclusive
	Limit    int
}

const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

// Matches reports whether e passes every set field of the filter.
func (f Filter) Matches(e Entry) bool {
	switch {
	case f.AgentID != "" && e.AgentID != f.AgentID:
		return false
	case f.Tool != "" && e.Tool != f.Tool:
		return false
	case f.Decision != "" && e.Decision != f.Decision:
		return false
	case !f.Since.IsZero() && e.Time.Before(f.Since):
		return false
	case !f.Until.IsZero() && !e.Time.Before(f.Until):
		return false
	}
	return true
}

// EffectiveLimit returns the limit to apply, after defaults and the cap.
func (f Filter) EffectiveLimit() int {
	switch {
	case f.Limit <= 0:
		return DefaultLimit
	case f.Limit > MaxLimit:
		return MaxLimit
	}
	return f.Limit
}

// ParseFilter reads ?agent=&tool=&decision=&since=&until=&limit= from a URL.
// Times are RFC 3339, e.g. 2026-11-02T10:00:00Z.
func ParseFilter(q url.Values) (Filter, error) {
	f := Filter{
		AgentID:  q.Get("agent"),
		Tool:     q.Get("tool"),
		Decision: policy.Action(q.Get("decision")),
	}
	switch f.Decision {
	case "", policy.ActionAllow, policy.ActionAsk, policy.ActionDeny:
	default:
		return Filter{}, fmt.Errorf("decision must be allow, ask or deny")
	}

	var err error
	if f.Since, err = parseTime(q.Get("since")); err != nil {
		return Filter{}, fmt.Errorf("since: %w", err)
	}
	if f.Until, err = parseTime(q.Get("until")); err != nil {
		return Filter{}, fmt.Errorf("until: %w", err)
	}
	if s := q.Get("limit"); s != "" {
		if f.Limit, err = strconv.Atoi(s); err != nil || f.Limit < 1 {
			return Filter{}, fmt.Errorf("limit must be a positive number")
		}
	}
	return f, nil
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("want an RFC 3339 time like 2026-11-02T10:00:00Z")
	}
	return t, nil
}

// Lister is the part of the store the audit endpoint needs. Go interfaces
// are usually declared by the code that uses them, like this one.
type Lister interface {
	ListAudit(ctx context.Context, f Filter) ([]Entry, error)
}

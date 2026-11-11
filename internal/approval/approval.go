// Package approval holds risky tool calls until a human decides. An approval
// is bound to one agent, one tool and one exact set of arguments (by hash),
// and once approved it lets exactly one retry through within a time window.
// An approval nobody decides on expires after a timeout.
package approval

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
)

// Status is where an approval is in its life.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
	StatusUsed     Status = "used"    // approved, and the retry has gone through
	StatusExpired  Status = "expired" // nobody decided before the timeout
)

// Errors returned by a Repository and the Service.
var (
	ErrNotFound   = errors.New("approval not found")
	ErrNotPending = errors.New("approval has already been decided")
	ErrExpired    = errors.New("approval expired before anyone decided")
	ErrNotUsable  = errors.New("approval is not approved, has expired, or was already used")
	ErrBadToken   = errors.New("approver token is missing or wrong")
	ErrNoApprover = errors.New("no approvers are configured for this owner")
	// ErrTooManyPending means the agent already has as many approvals
	// waiting as it may, so no new one was opened and nobody was notified.
	ErrTooManyPending = errors.New("too many pending approvals")
	// ErrNotRecorded means the audit log couldn't take the decision, so it
	// wasn't made. The approval is still pending and the approver can retry.
	ErrNotRecorded = errors.New("the decision could not be recorded in the audit log, so it was not made")
)

// Auditor is the part of the store the service needs to record decisions.
type Auditor interface {
	AppendAudit(ctx context.Context, e audit.Entry) (audit.Entry, error)
}

// ApproverToken lets one named approver decide. Only a hash of the secret is kept.
type ApproverToken struct {
	Approver string   // e.g. ada@acme.example
	Hash     [32]byte // sha256 of the secret in that approver's link
}

// Approval is one held call waiting for, or carrying, a human decision.
type Approval struct {
	ID         string          `json:"id"`
	Tokens     []ApproverToken `json:"-"` // one per approver; the secrets themselves are never stored
	AgentID    string          `json:"agent_id"`
	OwnerID    string          `json:"owner_id"`
	Tool       string          `json:"tool"`
	ParamsHash string          `json:"params_hash"`
	Summary    string          `json:"summary"`
	Arguments  json.RawMessage `json:"-"` // canonical JSON, shown to the approver only, never logged
	Level      policy.Level    `json:"level"`
	Score      int             `json:"score"`             // consequence score, 0 to 100
	Reasons    []string        `json:"reasons,omitempty"` // why it scored that, shown to the approver
	Rule       string          `json:"rule"`
	Status     Status          `json:"status"`
	CreatedAt  time.Time       `json:"created_at"`
	ExpiresAt  time.Time       `json:"expires_at"` // a decision must come before this
	DecidedAt  time.Time       `json:"decided_at,omitempty"`
	DecidedBy  string          `json:"decided_by,omitempty"`
	ValidUntil time.Time       `json:"valid_until,omitempty"` // set when approved
	UsedAt     time.Time       `json:"used_at,omitempty"`
}

// Expired reports whether an approved call's retry window has passed.
func (a Approval) Expired(now time.Time) bool {
	return a.Status == StatusApproved && !now.Before(a.ValidUntil)
}

// Overdue reports whether a pending approval is past its decision deadline.
// It may still read "pending" until the next sweep marks it expired.
func (a Approval) Overdue(now time.Time) bool {
	return a.Status == StatusPending && !a.ExpiresAt.IsZero() && !now.Before(a.ExpiresAt)
}

// AuditEntry describes something that happened to this approval, for the audit log.
func (a Approval) AuditEntry(at time.Time, outcome audit.Outcome, detail string) audit.Entry {
	return audit.Entry{
		Time: at, AgentID: a.AgentID, OwnerID: a.OwnerID, Tool: a.Tool,
		ParamsHash: a.ParamsHash, Summary: a.Summary, Level: a.Level, Score: a.Score, Decision: policy.ActionAsk,
		Rule: a.Rule, Outcome: outcome, ApprovalID: a.ID, Detail: detail,
	}
}

// Repository stores approvals. Implementations must make DecideApproval and
// UseApproval atomic, so two concurrent retries can't both use one approval.
type Repository interface {
	CreateApproval(ctx context.Context, a Approval) error
	GetApproval(ctx context.Context, id string) (Approval, error)
	// FindLatestApproval returns the newest approval for this agent, tool and
	// arguments, or ErrNotFound.
	FindLatestApproval(ctx context.Context, agentID, tool, paramsHash string) (Approval, error)
	// DecideApproval moves a pending approval that isn't overdue at time at
	// to approved or rejected, or returns ErrNotPending.
	DecideApproval(ctx context.Context, id string, status Status, by string, at, validUntil time.Time) (Approval, error)
	// UseApproval marks an approved, unexpired approval as used, or returns ErrNotUsable.
	UseApproval(ctx context.Context, id string, at time.Time) (Approval, error)
	// CountPendingApprovals counts this agent's approvals that are pending
	// and not yet overdue at now.
	CountPendingApprovals(ctx context.Context, agentID string, now time.Time) (int, error)
	// ExpireApprovals marks every approval overdue at now as expired and
	// returns them. Each approval is returned by exactly one call, even with
	// several servers sharing the store.
	ExpireApprovals(ctx context.Context, now time.Time) ([]Approval, error)
}

// Request describes a held call.
type Request struct {
	AgentID    string
	OwnerID    string
	Tool       string
	ParamsHash string
	Summary    string
	Arguments  json.RawMessage // canonical JSON
	Level      policy.Level
	Score      int
	Reasons    []string
	Rule       string
}

// State is the answer to "may this held call go through now?".
type State int

const (
	StatePending  State = iota // waiting for a human (iota numbers constants 0, 1, 2...)
	StateApproved              // approved and now used up: forward the call
	StateRejected              // a human said no
)

// Result is what Check decided, and the approval it was based on.
type Result struct {
	State    State
	Approval Approval
}

// Options configures a Service.
type Options struct {
	Repo      Repository
	Audit     Auditor             // records every decision; Decide refuses to work without it
	Approvers map[string][]string // owner ID -> approver emails
	Validity  time.Duration       // how long an approval stays usable after it's granted
	Timeout   time.Duration       // how long a held call waits for a decision; 0 means forever
	// MaxPending caps how many approvals one agent may have waiting at once;
	// 0 means no cap. Without it, changing an argument slightly each time
	// opens a new approval and emails every approver: approval fatigue.
	MaxPending int
	PublicURL  string   // base URL for links, e.g. http://localhost:8080
	Notifier   Notifier // delivers approver links; nil means LogNotifier
	Log        *slog.Logger
	Now        func() time.Time
}

// Service implements the approval rules on top of a Repository.
type Service struct {
	repo      Repository
	audit     Auditor
	approvers map[string][]string
	validity  time.Duration
	timeout   time.Duration
	maxPend   int
	openMu    sync.Mutex // makes counting and opening one step within this process
	publicURL string
	notifier  Notifier
	log       *slog.Logger
	now       func() time.Time
}

func NewService(opts Options) *Service {
	s := &Service{
		repo:      opts.Repo,
		audit:     opts.Audit,
		approvers: opts.Approvers,
		validity:  opts.Validity,
		timeout:   opts.Timeout,
		maxPend:   opts.MaxPending,
		publicURL: strings.TrimSuffix(opts.PublicURL, "/"),
		notifier:  opts.Notifier,
		log:       opts.Log,
		now:       opts.Now,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.notifier == nil {
		s.notifier = LogNotifier{Log: opts.Log}
	}
	return s
}

// Validity returns how long an approval stays usable after it's granted.
func (s *Service) Validity() time.Duration { return s.validity }

// Timeout returns how long a held call waits for a decision.
func (s *Service) Timeout() time.Duration { return s.timeout }

// MaxPending returns how many approvals one agent may have waiting; 0 means no cap.
func (s *Service) MaxPending() int { return s.maxPend }

// Check decides whether a held call may go through. It reuses a pending
// approval for the same call, lets one retry through after approval, and
// opens a new approval when there is none (or the last one expired or was used).
func (s *Service) Check(ctx context.Context, req Request) (Result, error) {
	now := s.now().UTC()
	latest, err := s.repo.FindLatestApproval(ctx, req.AgentID, req.Tool, req.ParamsHash)
	switch {
	case errors.Is(err, ErrNotFound):
		// nothing yet: open a new approval below
	case err != nil:
		return Result{}, err
	case latest.Overdue(now):
		// Nobody decided in time. The sweep marks it expired; ask afresh.
	case latest.Status == StatusPending:
		return Result{State: StatePending, Approval: latest}, nil
	case latest.Status == StatusApproved && !latest.Expired(now):
		used, err := s.repo.UseApproval(ctx, latest.ID, now)
		if err == nil {
			return Result{State: StateApproved, Approval: used}, nil
		}
		if !errors.Is(err, ErrNotUsable) {
			return Result{}, err
		}
		// Another retry used it a moment ago: fall through and ask again.
	case latest.Status == StatusRejected && now.Before(latest.DecidedAt.Add(s.validity)):
		// A recent "no" stands, so the agent can't pester the approver.
		return Result{State: StateRejected, Approval: latest}, nil
	}
	created, err := s.open(ctx, req, now)
	if err != nil {
		return Result{}, err
	}
	return Result{State: StatePending, Approval: created}, nil
}

func (s *Service) open(ctx context.Context, req Request, now time.Time) (Approval, error) {
	approvers := s.approvers[req.OwnerID]
	if len(approvers) == 0 {
		return Approval{}, fmt.Errorf("%w: %s", ErrNoApprover, req.OwnerID)
	}
	id, err := randomString(8, hex.EncodeToString)
	if err != nil {
		return Approval{}, err
	}
	// Each approver gets their own secret, so a decision names who made it.
	links := make(map[string]string, len(approvers))
	tokens := make([]ApproverToken, 0, len(approvers))
	for _, approver := range approvers {
		token, err := randomString(32, base64.RawURLEncoding.EncodeToString)
		if err != nil {
			return Approval{}, err
		}
		tokens = append(tokens, ApproverToken{Approver: approver, Hash: sha256.Sum256([]byte(token))})
		links[approver] = token
	}
	a := Approval{
		ID:         "apr_" + id,
		Tokens:     tokens,
		AgentID:    req.AgentID,
		OwnerID:    req.OwnerID,
		Tool:       req.Tool,
		ParamsHash: req.ParamsHash,
		Summary:    req.Summary,
		Arguments:  req.Arguments,
		Level:      req.Level,
		Score:      req.Score,
		Reasons:    req.Reasons,
		Rule:       req.Rule,
		Status:     StatusPending,
		CreatedAt:  now,
	}
	if s.timeout > 0 {
		a.ExpiresAt = now.Add(s.timeout)
	}
	if err := s.create(ctx, a, now); err != nil {
		return Approval{}, err
	}
	// Each link carries a secret: whoever has it can decide as that approver.
	for _, approver := range approvers {
		s.notifier.Notify(ctx, Notice{Approval: a, Approver: approver, Link: s.ApproverURL(a.ID, links[approver]), Validity: s.validity})
	}
	s.log.Info("approval requested", "approval_id", a.ID, "agent", a.AgentID, "tool", a.Tool,
		"rule", a.Rule, "approvers", len(approvers))
	return a, nil
}

// create saves a new approval unless the agent is at its cap. The lock stops
// parallel calls from one process all passing the count together. Several
// servers sharing one database can still overshoot by a few in a burst.
func (s *Service) create(ctx context.Context, a Approval, now time.Time) error {
	if s.maxPend <= 0 {
		return s.repo.CreateApproval(ctx, a)
	}
	s.openMu.Lock()
	defer s.openMu.Unlock()
	n, err := s.repo.CountPendingApprovals(ctx, a.AgentID, now)
	if err != nil {
		return err
	}
	if n >= s.maxPend {
		return fmt.Errorf("%w: %s has %d waiting", ErrTooManyPending, a.AgentID, n)
	}
	return s.repo.CreateApproval(ctx, a)
}

// View returns an approval and, if token belongs to one of its approvers,
// that approver's email. An empty approver means read-only.
func (s *Service) View(ctx context.Context, id, token string) (Approval, string, error) {
	a, err := s.repo.GetApproval(ctx, id)
	if err != nil {
		return Approval{}, "", err
	}
	return a, approverFor(a, token), nil
}

// Decide records the decision of the approver whose token this is.
//
// The audit entry is written first and the decision saved second, so the log
// never misses a decision: if the entry can't be written, nothing is decided
// (ErrNotRecorded). If saving then fails, usually because another approver
// decided a moment earlier, a second entry says the first didn't take effect.
// The log is append-only, so it corrects itself rather than being edited.
func (s *Service) Decide(ctx context.Context, id, token string, approve bool) (Approval, error) {
	a, err := s.repo.GetApproval(ctx, id)
	if err != nil {
		return Approval{}, err
	}
	by := approverFor(a, token)
	if by == "" {
		return Approval{}, ErrBadToken
	}
	now := s.now().UTC()
	if a.Overdue(now) || a.Status == StatusExpired {
		return Approval{}, ErrExpired
	}
	if a.Status != StatusPending {
		// Already decided: refuse before writing anything, so a double
		// click doesn't add entries. A true race is handled below.
		return Approval{}, ErrNotPending
	}
	status, validUntil, outcome := StatusRejected, time.Time{}, audit.OutcomeDeclined
	if approve {
		status, validUntil, outcome = StatusApproved, now.Add(s.validity), audit.OutcomeApproved
	}
	if err := s.record(ctx, a.AuditEntry(now, outcome, "decided by "+by)); err != nil {
		s.log.Error("audit write failed, so the decision was not made", "approval_id", id, "by", by, "err", err)
		return Approval{}, ErrNotRecorded
	}
	decided, err := s.repo.DecideApproval(ctx, id, status, by, now, validUntil)
	if err != nil {
		why := "saving it failed"
		if errors.Is(err, ErrNotPending) {
			why = "another decision came first"
		}
		detail := fmt.Sprintf("%s by %s was not applied: %s", status, by, why)
		if aerr := s.record(ctx, a.AuditEntry(now, audit.OutcomeNotApplied, detail)); aerr != nil {
			s.log.Error("audit write failed for a decision that was not applied", "approval_id", id, "err", aerr)
		}
		return Approval{}, err
	}
	s.log.Info("approval decided", "approval_id", id, "status", status, "by", by, "tool", a.Tool, "agent", a.AgentID)
	return decided, nil
}

// record appends an audit entry. Without an auditor nothing can be
// recorded, which counts as a failure: decisions must not go unaudited.
func (s *Service) record(ctx context.Context, e audit.Entry) error {
	if s.audit == nil {
		return errors.New("approval: no audit log configured")
	}
	_, err := s.audit.AppendAudit(ctx, e)
	return err
}

// ExpireOverdue marks every approval that's past its deadline as expired
// and returns them, so the caller can record each one once.
func (s *Service) ExpireOverdue(ctx context.Context) ([]Approval, error) {
	return s.repo.ExpireApprovals(ctx, s.now().UTC())
}

// Now returns the service's current time, so pages agree with Check about expiry.
func (s *Service) Now() time.Time { return s.now().UTC() }

// StatusURL is the read-only page the agent can share with its user.
func (s *Service) StatusURL(id string) string {
	return s.publicURL + "/approvals/" + id
}

// ApproverURL is the page with Approve and Reject buttons. It carries the secret.
func (s *Service) ApproverURL(id, token string) string {
	return s.StatusURL(id) + "?token=" + token
}

// approverFor returns the approver whose secret token is, or "".
func approverFor(a Approval, token string) string {
	if token == "" {
		return ""
	}
	got := sha256.Sum256([]byte(token))
	for _, t := range a.Tokens {
		if subtle.ConstantTimeCompare(got[:], t.Hash[:]) == 1 {
			return t.Approver
		}
	}
	return ""
}

// randomString returns n random bytes encoded by encode.
func randomString(n int, encode func([]byte) string) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("approval: random: %w", err)
	}
	return encode(b), nil
}

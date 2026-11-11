// Package gate decides gated calls, whatever transport they came by. It
// assesses a call's consequence, runs it past the policy, opens or checks an
// approval when the policy asks, keeps limits counted and writes the audit
// log.
//
// It never answers the agent. Each transport is an adapter that parses
// calls its own way, asks the gate, and words the answer the way its
// transport needs: the HTTP proxy sends a tool result or a JSON-RPC error,
// and a hook would send a hook decision.
package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/consequence"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/store"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// Options configures a Gate.
type Options struct {
	Engine *policy.Engine
	// Resolver assesses each call's consequence before the policy decides.
	// nil means the engine's own, built from the tools map.
	Resolver  consequence.Resolver
	Store     store.Store
	Approvals *approval.Service
	Log       *slog.Logger
	Now       func() time.Time // nil means time.Now; tests pass a fixed clock
}

// Gate decides calls. It is safe for concurrent use.
type Gate struct {
	engine    *policy.Engine
	resolver  consequence.Resolver
	store     store.Store
	approvals *approval.Service
	log       *slog.Logger
	now       func() time.Time
	limits    keyedLocks // serializes calls covered by limit rules; see locks.go
}

// New builds a Gate.
func New(opts Options) (*Gate, error) {
	g := &Gate{
		engine:    opts.Engine,
		resolver:  opts.Resolver,
		store:     opts.Store,
		approvals: opts.Approvals,
		log:       opts.Log,
		now:       opts.Now,
	}
	if g.engine == nil || g.store == nil || g.approvals == nil || g.log == nil {
		return nil, fmt.Errorf("gate: Engine, Store, Approvals and Log are required")
	}
	if g.now == nil {
		g.now = time.Now
	}
	if g.resolver == nil {
		g.resolver = g.engine.Static()
	}
	return g, nil
}

// Request is one gated call, already parsed and checked by the adapter.
type Request struct {
	AgentID string
	OwnerID string
	// Name is what the policy matches: a tool name, "resource:<uri>" or
	// "prompt:<name>".
	Name    string
	RawArgs json.RawMessage // exactly as sent, for the hash; empty or null means none
	Args    map[string]any  // decoded, for the policy
}

// Verdict is what the gate decided.
type Verdict int

const (
	// Allowed: the policy allows the call, or a human approved it. The
	// adapter calls Result.Admit, and goes ahead only if that succeeds.
	Allowed  Verdict = iota + 1
	Denied           // a policy rule denies it
	Held             // waiting for a human; Result.Approval names the request
	Declined         // a human said no
	// TooManyPending: the policy asks, but the agent already has as many
	// requests waiting as allowed, so no new one was opened.
	TooManyPending
)

// Result is a decided call. Every verdict except Allowed is already in the
// audit log when Decide returns.
type Result struct {
	Verdict  Verdict
	Decision policy.Decision
	// Entry is the audit entry written, or for Allowed the one Admit writes.
	Entry audit.Entry
	// Approval is set when the policy asked: the request that is held,
	// declined or was approved. ApprovedBy names who approved it.
	Approval   approval.Approval
	ApprovedBy string

	g       *Gate
	call    policy.Call
	release func()
}

// Error says why the gate could not decide or record a call. The call must
// not go ahead.
type Error struct {
	// What says what failed, in words the agent can be shown:
	// "usage limits unavailable".
	What string
	// BadArguments means the arguments themselves were the problem, rather
	// than something the gate depends on being unavailable.
	BadArguments bool
	Err          error // the cause, for logs; never shown to the agent
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.What
	}
	return e.What + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// Decide assesses and decides one call. On a nil error the caller must call
// Result.Release once it is done with the result, typically by defer:
// an allowed call holds this agent's limit locks until Admit or Release.
func (g *Gate) Decide(ctx context.Context, req Request) (*Result, error) {
	entry := audit.Entry{Time: g.now().UTC(), AgentID: req.AgentID, OwnerID: req.OwnerID}

	hash, err := verify.ParamsHash(req.RawArgs)
	if err != nil { // the adapter has already parsed them, but never decide on unhashed arguments
		return nil, &Error{What: "arguments could not be hashed", BadArguments: true, Err: err}
	}
	// Assess before taking any lock: a resolver may be slow (a map lookup),
	// and the assessment doesn't depend on other calls.
	assessment, err := g.resolver.Assess(ctx, req.Name, req.Args)
	if err == nil {
		err = assessment.Validate()
	}
	if err != nil {
		g.log.Error("consequence assessment failed", "tool", req.Name, "err", err)
		return nil, &Error{What: "consequence could not be assessed", Err: err}
	}
	// With limit rules, this agent's calls in each limit scope that covers
	// this tool go one at a time until the call is recorded, so parallel
	// calls can't all fit under a limit. No scopes means no locks.
	release := g.limits.lockAll(req.AgentID+"\x00", g.engine.UsageScopes(req.Name))
	res := &Result{g: g, release: release}
	res.call = policy.Call{AgentID: req.AgentID, Tool: req.Name, Args: req.Args, At: entry.Time, Consequence: assessment}

	decision, err := g.engine.Decide(ctx, res.call, g.store)
	if err != nil {
		release()
		g.log.Error("policy decision failed", "tool", req.Name, "err", err)
		return nil, &Error{What: "usage limits unavailable", Err: err}
	}
	entry.Tool = req.Name
	entry.ParamsHash = hash
	entry.Summary = Summarize(req.Name, req.Args)
	entry.Level = decision.Level
	entry.Score = decision.Consequence.Score
	entry.Decision = decision.Action
	entry.Rule = decision.Rule
	res.Decision, res.Entry = decision, entry

	switch decision.Action {
	case policy.ActionAllow:
		res.Verdict = Allowed
		return res, nil
	case policy.ActionDeny:
		res.finish(ctx, Denied, audit.OutcomeBlocked, "")
		return res, nil
	default: // ActionAsk
		if err := g.ask(ctx, req, res); err != nil {
			release()
			return nil, err
		}
		return res, nil
	}
}

// ask opens or checks the approval for a call the policy holds for a human.
// An approved call comes back Allowed, for one retry of the exact same call
// (same agent, tool and argument hash).
func (g *Gate) ask(ctx context.Context, req Request, res *Result) error {
	args := req.RawArgs
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage("{}")
	}
	canonical, err := verify.Canonicalize(args)
	if err != nil {
		return &Error{What: "arguments could not be canonicalized", BadArguments: true, Err: err}
	}
	e := res.Entry
	check, err := g.approvals.Check(ctx, approval.Request{
		AgentID: e.AgentID, OwnerID: e.OwnerID, Tool: e.Tool, ParamsHash: e.ParamsHash,
		Summary: e.Summary, Arguments: canonical, Level: e.Level, Rule: e.Rule,
		Score: e.Score, Reasons: res.call.Consequence.Reasons,
	})
	if errors.Is(err, approval.ErrTooManyPending) {
		// Refused, not held: holding it would email the approvers yet again.
		res.finish(ctx, TooManyPending, audit.OutcomeBlocked, "too many pending approvals")
		return nil
	}
	if err != nil {
		g.log.Error("approval check failed", "tool", e.Tool, "err", err)
		return &Error{What: "approvals unavailable", Err: err}
	}
	res.Approval = check.Approval
	res.Entry.ApprovalID = check.Approval.ID

	switch check.State {
	case approval.StateApproved:
		res.Verdict, res.ApprovedBy = Allowed, check.Approval.DecidedBy
	case approval.StateRejected:
		res.finish(ctx, Declined, audit.OutcomeDeclined, "")
	default: // StatePending
		res.finish(ctx, Held, audit.OutcomeHeld, "")
	}
	return nil
}

// finish sets a verdict that stops the call, records it and frees the
// locks. The call is refused whether or not the audit write succeeds.
func (r *Result) finish(ctx context.Context, v Verdict, outcome audit.Outcome, detail string) {
	r.Verdict = v
	r.Entry.Outcome, r.Entry.Detail = outcome, detail
	_ = r.g.Record(ctx, r.Entry)
	r.release()
}

// Admit records an allowed call before the adapter lets it go ahead: it
// counts the call towards every limit that covers it, writes the audit
// entry as forwarded, and frees the call's limit locks. receiptID names the
// receipt the adapter will attach, or is empty.
//
// On an error the call must not go ahead. Usage is counted first, so a
// failed audit write over-counts the call (the safe way round) rather than
// letting it through uncounted.
func (r *Result) Admit(ctx context.Context, receiptID string) error {
	if r.Verdict != Allowed {
		return fmt.Errorf("gate: Admit called on a call that is not allowed")
	}
	for _, u := range r.g.engine.UsageRecords(r.call) {
		if err := r.g.store.RecordUsage(ctx, u); err != nil {
			r.g.log.Error("usage write failed", "tool", r.Entry.Tool, "scope", u.Tool, "err", err)
			return &Error{What: "usage log unavailable", Err: err}
		}
	}
	r.Entry.Outcome = audit.OutcomeForwarded
	r.Entry.ReceiptID = receiptID
	if err := r.g.Record(ctx, r.Entry); err != nil {
		return &Error{What: "audit log unavailable", Err: err}
	}
	r.release() // counted: the next call may be decided while this one runs
	return nil
}

// Release frees the call's limit locks. It is safe to call more than once,
// and after Admit.
func (r *Result) Release() { r.release() }

// Record saves an audit entry and logs the decision. Adapters use it for
// calls they reject before asking the gate. A zero Time is set to now.
// Arguments are never logged, only their hash and a summary of which keys
// were present.
func (g *Gate) Record(ctx context.Context, e audit.Entry) error {
	if e.Time.IsZero() {
		e.Time = g.now().UTC()
	}
	saved, err := g.store.AppendAudit(ctx, e)
	if err != nil {
		g.log.Error("audit write failed", "agent", e.AgentID, "tool", e.Tool, "err", err)
		return err
	}
	g.log.Info("decision", "audit_id", saved.ID, "agent", e.AgentID, "tool", e.Tool,
		"decision", e.Decision, "rule", e.Rule, "score", e.Score, "outcome", e.Outcome, "params_hash", e.ParamsHash,
		"approval_id", e.ApprovalID, "receipt_id", e.ReceiptID)
	return nil
}

// Summarize describes a call without revealing argument values,
// e.g. "payments.refund with amount, charge_id".
func Summarize(name string, args map[string]any) string {
	if len(args) == 0 {
		return name + " with no arguments"
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return name + " with " + strings.Join(keys, ", ")
}

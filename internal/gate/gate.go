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
	"github.com/matutozi/consequence-os/internal/toolpin"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// Options configures a Gate.
type Options struct {
	Engine *policy.Engine
	// Resolver assesses each call's consequence before the policy decides.
	// nil means the engine's own, built from the tools map.
	Resolver consequence.Resolver
	Store    store.Store
	// Approvals holds asked calls for a human to approve by link. nil
	// means there is no approval service: the person is at the keyboard,
	// and an asked call comes back AskUser for the adapter to ask them.
	Approvals *approval.Service
	// Tools checks calls against the upstream's pinned tool definitions:
	// arguments the accepted schema doesn't name are refused, and a tool
	// whose definition changed asks. nil means nothing is pinned, as for
	// the Claude Code hook, whose tools come from no listing.
	Tools *toolpin.Service
	// Observe is observe mode (shadow mode): calls are decided and
	// audited as usual, but none is stopped. A call the policy would have
	// denied, held or refused comes back Allowed with Observed set, and
	// is recorded as observed, with what would have happened. No approval
	// is opened. Checks that keep a request unambiguous, and failures of
	// what the decision depends on, still stop calls: they're not policy.
	Observe bool
	Log     *slog.Logger
	Now     func() time.Time // nil means time.Now; tests pass a fixed clock
}

// Gate decides calls. It is safe for concurrent use.
type Gate struct {
	engine    *policy.Engine
	resolver  consequence.Resolver
	store     store.Store
	approvals *approval.Service
	tools     *toolpin.Service
	observe   bool
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
		tools:     opts.Tools,
		observe:   opts.Observe,
		log:       opts.Log,
		now:       opts.Now,
	}
	if g.engine == nil || g.store == nil || g.log == nil {
		return nil, fmt.Errorf("gate: Engine, Store and Log are required")
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
	// AskUser: the policy asks and the gate has no approval service. The
	// adapter calls Result.Admit, then asks the person at the keyboard.
	// The call counts towards limits whatever they answer, since the gate
	// never learns it: limits over-count rather than under-count.
	AskUser
	// Invalid: the arguments don't fit the tool's pinned input schema, so
	// the policy never saw the call. Result.Reason says how.
	Invalid
)

// Result is a decided call. Every verdict except Allowed and AskUser is
// already in the audit log when Decide returns.
type Result struct {
	Verdict  Verdict
	Decision policy.Decision
	// Entry is the audit entry written, or for Allowed and AskUser the one
	// Admit writes. An adapter may set its Detail before calling Admit.
	Entry audit.Entry
	// Approval is set when the policy asked: the request that is held,
	// declined or was approved. ApprovedBy names who approved it.
	Approval   approval.Approval
	ApprovedBy string
	// Reason says why an Invalid call was refused, in words for the agent.
	Reason string
	// ToolChanged means the upstream listed a definition of this tool
	// other than the accepted one, so the call asks (or a deny rule still
	// denies it) until a person accepts the change.
	ToolChanged bool
	// Observed means observe mode let through a call the policy would
	// have stopped; Would says how it would have been stopped, e.g.
	// "would have been blocked". The adapter forwards it without a
	// receipt: a receipt says the policy allowed the call, and it didn't.
	Observed bool
	Would    string

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
	toolChanged, invalid := false, ""
	if g.tools != nil && !policy.IsRead(req.Name) {
		st, problem, err := g.tools.Check(ctx, req.Name, req.Args)
		if err != nil {
			g.log.Error("tool pin lookup failed", "tool", req.Name, "err", err)
			return nil, &Error{What: "tool definitions unavailable", Err: err}
		}
		if problem != "" && !g.observe {
			entry.Tool, entry.ParamsHash, entry.Summary = req.Name, hash, Summarize(req.Name, req.Args)
			res := &Result{g: g, release: func() {}, Reason: problem}
			res.Entry = entry
			res.finish(ctx, Invalid, audit.OutcomeRejected, problem)
			return res, nil
		}
		invalid = problem // in observe mode, recorded below and not stopped
		toolChanged = st == toolpin.Changed
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
	if toolChanged {
		// What the tool does now is unknown: assess it as a tool nobody
		// has listed, so the score, the level and rules on them say so.
		assessment.Reversibility = consequence.None
		assessment.Score = max(assessment.Score, consequence.DefaultIrreversibleScore)
		assessment.Reasons = append(assessment.Reasons, fmt.Sprintf(
			"%s's definition changed since it was accepted, so it counts as irreversible until the change is accepted.", req.Name))
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
	if toolChanged && decision.Action != policy.ActionDeny {
		// The rules were written for the definition that was accepted,
		// not this one, so even an allow asks.
		decision.Action, decision.Rule = policy.ActionAsk, toolpin.RuleChanged
	}
	res.ToolChanged = toolChanged
	entry.Tool = req.Name
	entry.ParamsHash = hash
	entry.Summary = Summarize(req.Name, req.Args)
	entry.Level = decision.Level
	entry.Score = decision.Consequence.Score
	entry.Decision = decision.Action
	entry.Rule = decision.Rule
	res.Decision, res.Entry = decision, entry

	if g.observe {
		if would := g.would(decision.Action, invalid); would != "" {
			res.Verdict, res.Observed, res.Would = Allowed, true, would
			return res, nil
		}
	}
	switch decision.Action {
	case policy.ActionAllow:
		res.Verdict = Allowed
		return res, nil
	case policy.ActionDeny:
		res.finish(ctx, Denied, audit.OutcomeBlocked, "")
		return res, nil
	default: // ActionAsk
		if g.approvals == nil {
			res.Verdict = AskUser
			return res, nil
		}
		if err := g.ask(ctx, req, res); err != nil {
			release()
			return nil, err
		}
		return res, nil
	}
}

// would says how a call would have been stopped, in observe mode, or ""
// when it wouldn't have been.
func (g *Gate) would(action policy.Action, invalid string) string {
	switch {
	case invalid != "":
		return "would have been refused: " + invalid
	case action == policy.ActionDeny:
		return "would have been blocked"
	case action == policy.ActionAsk && g.approvals == nil:
		return "would have asked the user"
	case action == policy.ActionAsk:
		return "would have been held for approval"
	}
	return ""
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
// receipt the adapter will attach, or is empty. For AskUser it does the
// same, with the outcome asked_user.
//
// On an error the call must not go ahead. Usage is counted first, so a
// failed audit write over-counts the call (the safe way round) rather than
// letting it through uncounted.
func (r *Result) Admit(ctx context.Context, receiptID string) error {
	outcome := audit.OutcomeForwarded
	switch r.Verdict {
	case Allowed:
		if r.Observed {
			outcome = audit.OutcomeObserved
			detail := "observe mode: " + r.Would
			if r.Entry.Detail != "" {
				detail += "; " + r.Entry.Detail // the adapter's own note
			}
			r.Entry.Detail = detail
		}
	case AskUser:
		outcome = audit.OutcomeAskedUser
	default:
		return fmt.Errorf("gate: Admit called on a call that is not allowed")
	}
	for _, u := range r.g.engine.UsageRecords(r.call) {
		if err := r.g.store.RecordUsage(ctx, u); err != nil {
			r.g.log.Error("usage write failed", "tool", r.Entry.Tool, "scope", u.Tool, "err", err)
			return &Error{What: "usage log unavailable", Err: err}
		}
	}
	r.Entry.Outcome = outcome
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

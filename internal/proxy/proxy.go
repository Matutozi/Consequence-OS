// Package proxy is Guard 1: it sits between an agent and the upstream MCP
// server, passes ordinary traffic through untouched, and runs every
// tools/call, resources/read and prompts/get past the policy engine first.
package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/config"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/receipt"
	"github.com/matutozi/consequence-os/internal/store"
	"github.com/matutozi/consequence-os/pkg/verify"
)

const maxBodyBytes = 4 << 20 // 4 MiB

// Options configures a Proxy.
type Options struct {
	Upstream       string
	Agents         []config.Agent
	AllowedOrigins []string
	Engine         *policy.Engine
	Store          store.Store
	Approvals      *approval.Service
	Receipts       *receipt.Issuer
	Log            *slog.Logger
	Now            func() time.Time // nil means time.Now; tests pass a fixed clock
}

// Proxy implements http.Handler for the /mcp endpoint.
type Proxy struct {
	engine    *policy.Engine
	store     store.Store
	approvals *approval.Service
	receipts  *receipt.Issuer
	log       *slog.Logger
	now       func() time.Time
	agents    map[[32]byte]config.Agent // keyed by sha256 of the API key
	origins   map[string]bool
	rp        *httputil.ReverseProxy
	limits    keyedLocks // serializes calls covered by limit rules; see locks.go
}

// New builds a Proxy.
func New(opts Options) (*Proxy, error) {
	upstream, err := url.Parse(opts.Upstream)
	if err != nil || upstream.Host == "" {
		return nil, fmt.Errorf("proxy: bad upstream URL %q", opts.Upstream)
	}
	p := &Proxy{
		engine:    opts.Engine,
		store:     opts.Store,
		approvals: opts.Approvals,
		receipts:  opts.Receipts,
		log:       opts.Log,
		now:       opts.Now,
		agents:    make(map[[32]byte]config.Agent, len(opts.Agents)),
		origins:   make(map[string]bool, len(opts.AllowedOrigins)),
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.engine == nil || p.store == nil || p.approvals == nil || p.receipts == nil || p.log == nil {
		return nil, fmt.Errorf("proxy: Engine, Store, Approvals, Receipts and Log are required")
	}
	for _, a := range opts.Agents {
		// Looking agents up by a hash of the key means we never compare raw
		// keys byte by byte, which could leak timing information.
		p.agents[sha256.Sum256([]byte(a.APIKey))] = a
	}
	for _, o := range opts.AllowedOrigins {
		p.origins[strings.TrimSuffix(o, "/")] = true
	}
	p.rp = newReverseProxy(upstream, p.log)
	return p, nil
}

// ServeHTTP is the whole request flow: authenticate, check the origin, then
// either pass the message through or run it past policy.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	agent, ok := p.authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="consequenceos"`)
		writeJSON(w, http.StatusUnauthorized, errorResponse(nil, codeInvalidRequest, "missing or unknown API key"))
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && !p.origins[origin] {
		// Required by the MCP spec to stop DNS rebinding attacks from web pages.
		writeJSON(w, http.StatusForbidden, errorResponse(nil, codeInvalidRequest, "origin not allowed"))
		return
	}
	if r.Method != http.MethodPost {
		p.forward(w, r, nil) // e.g. GET streams or DELETE for legacy sessions
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse(nil, codeInvalidRequest, "request body too large"))
		return
	}
	msg, rerr := parseMessage(body)
	if rerr != nil {
		writeJSON(w, rerr.status, errorResponse(nil, rerr.code, rerr.message))
		return
	}
	if !gated(msg.method) {
		if rerr := checkHeaders(r.Header, msg, nil); rerr != nil {
			writeJSON(w, rerr.status, errorResponse(msg.id, rerr.code, rerr.message))
			return
		}
		p.forward(w, r, body)
		return
	}
	p.handleCall(w, r, agent, msg, body)
}

// handleCall decides a gated request. Tool calls and reads take the same
// path: limits, deny, ask and the audit log all apply to both. Only allowed
// tool calls get a receipt.
func (p *Proxy) handleCall(w http.ResponseWriter, r *http.Request, agent config.Agent, msg message, body []byte) {
	entry := audit.Entry{Time: p.now().UTC(), AgentID: agent.ID, OwnerID: agent.OwnerID}

	call, rerr := parseCall(msg)
	if rerr == nil {
		rerr = checkHeaders(r.Header, msg, &call)
	}
	if rerr != nil {
		entry.Tool, entry.Outcome, entry.Detail = call.name, audit.OutcomeRejected, rerr.message
		_ = p.record(r.Context(), entry) // best effort: nothing is forwarded either way
		writeJSON(w, rerr.status, errorResponse(msg.id, rerr.code, rerr.message))
		return
	}

	hash, err := verify.ParamsHash(call.rawArgs)
	if err != nil { // can't happen after parseMessage validated the body, but never forward unhashed
		writeJSON(w, http.StatusBadRequest, errorResponse(msg.id, codeInvalidParams, "arguments could not be hashed"))
		return
	}
	// With limit rules, this agent's calls in each limit scope that covers
	// this tool go one at a time until the call is recorded, so parallel
	// calls can't all fit under a limit. No scopes means no locks.
	release := p.limits.lockAll(agent.ID+"\x00", p.engine.UsageScopes(call.name))
	defer release()

	pc := policy.Call{AgentID: agent.ID, Tool: call.name, Args: call.args, At: entry.Time}
	decision, err := p.engine.Decide(r.Context(), pc, p.store)
	if err != nil {
		p.log.Error("policy decision failed", "tool", call.name, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, errorResponse(msg.id, codeInternalError, "usage limits unavailable; call not forwarded"))
		return
	}
	entry.Tool = call.name
	entry.ParamsHash = hash
	entry.Summary = summarize(call)
	entry.Level = decision.Level
	entry.Decision = decision.Action
	entry.Rule = decision.Rule

	switch decision.Action {
	case policy.ActionAllow:
		p.forwardAllowed(w, r, msg, call, pc, entry, "", body, release)

	case policy.ActionDeny:
		entry.Outcome = audit.OutcomeBlocked
		_ = p.record(r.Context(), entry) // the call is refused whether or not this succeeds
		text := fmt.Sprintf("Blocked by ConsequenceOS: policy rule %q does not allow %s. Do not retry this call.", decision.Rule, call.what())
		refuse(w, msg, call, text)

	default: // ActionAsk
		p.handleAsk(w, r, msg, call, pc, entry, body, release)
	}
}

// handleAsk holds a call until a human approves it, then lets one retry of
// the exact same call (same agent, tool and argument hash) through.
func (p *Proxy) handleAsk(w http.ResponseWriter, r *http.Request, msg message, call toolCall, pc policy.Call, entry audit.Entry, body []byte, release func()) {
	args := call.rawArgs
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage("{}")
	}
	canonical, err := verify.Canonicalize(args)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse(msg.id, codeInvalidParams, "arguments could not be canonicalized"))
		return
	}
	res, err := p.approvals.Check(r.Context(), approval.Request{
		AgentID: entry.AgentID, OwnerID: entry.OwnerID, Tool: entry.Tool, ParamsHash: entry.ParamsHash,
		Summary: entry.Summary, Arguments: canonical, Level: entry.Level, Rule: entry.Rule,
	})
	if errors.Is(err, approval.ErrTooManyPending) {
		// Refused, not held: holding it would email the approvers yet again.
		entry.Outcome, entry.Detail = audit.OutcomeBlocked, "too many pending approvals"
		_ = p.record(r.Context(), entry)
		text := fmt.Sprintf("Refused by ConsequenceOS: this agent already has %d requests waiting for a human to approve, "+
			"the most allowed, so %s was not sent for approval. Do not retry it or similar calls now. "+
			"Tell the user requests are waiting for their decision, and try again after they decide.",
			p.approvals.MaxPending(), call.what())
		refuse(w, msg, call, text)
		return
	}
	if err != nil {
		p.log.Error("approval check failed", "tool", entry.Tool, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, errorResponse(msg.id, codeInternalError, "approvals unavailable; call not forwarded"))
		return
	}
	a := res.Approval
	entry.ApprovalID = a.ID

	switch res.State {
	case approval.StateApproved:
		p.forwardAllowed(w, r, msg, call, pc, entry, a.DecidedBy, body, release)

	case approval.StateRejected:
		entry.Outcome = audit.OutcomeDeclined
		_ = p.record(r.Context(), entry)
		text := fmt.Sprintf("Rejected: an approver declined %s (approval %s). Do not retry it; tell the user it was declined.", call.what(), a.ID)
		refuse(w, msg, call, text)

	default: // StatePending
		entry.Outcome = audit.OutcomeHeld
		_ = p.record(r.Context(), entry)
		text := fmt.Sprintf("Approval pending: %s needs a human to approve it (policy rule %q). "+
			"Approval ID: %s. Status: %s . "+
			"Tell the user this action is waiting for approval. Once it is approved, retry this exact call "+
			"with the same arguments within %s; it will then go through once.",
			call.what(), entry.Rule, a.ID, p.approvals.StatusURL(a.ID), approval.HumanDuration(p.approvals.Validity()))
		if !a.ExpiresAt.IsZero() {
			text += fmt.Sprintf(" If nobody decides by %s, the request expires.", a.ExpiresAt.Format(time.RFC3339))
		}
		refuse(w, msg, call, text)
	}
}

// forwardAllowed forwards an allowed or approved call. Tool calls carry a
// receipt; reads don't, because receipts are for actions and receivers
// check only tools/call.
func (p *Proxy) forwardAllowed(w http.ResponseWriter, r *http.Request, msg message, call toolCall, pc policy.Call, entry audit.Entry, approvedBy string, body []byte, release func()) {
	if call.isTool() {
		p.forwardWithReceipt(w, r, msg, pc, entry, approvedBy, body, release)
		return
	}
	if !p.count(w, r, msg, pc, entry) {
		return
	}
	entry.Outcome = audit.OutcomeForwarded
	if err := p.record(r.Context(), entry); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse(msg.id, codeInternalError, "audit log unavailable; call not forwarded"))
		return
	}
	release()
	p.forward(w, r, body)
}

// count records the call's usage for every limit scope that covers it. On
// failure it answers the agent and returns false: nothing goes uncounted.
func (p *Proxy) count(w http.ResponseWriter, r *http.Request, msg message, pc policy.Call, entry audit.Entry) bool {
	for _, u := range p.engine.UsageRecords(pc) {
		if err := p.store.RecordUsage(r.Context(), u); err != nil {
			p.log.Error("usage write failed", "tool", entry.Tool, "scope", u.Tool, "err", err)
			writeJSON(w, http.StatusServiceUnavailable, errorResponse(msg.id, codeInternalError, "usage log unavailable; call not forwarded"))
			return false
		}
	}
	return true
}

// forwardWithReceipt signs a receipt for an allowed or approved call, writes
// the audit entry, and forwards the call with the receipt attached in both
// the X-Consequence-Receipt header and params._meta.consequenceReceipt.
// Any failure stops the call: nothing is forwarded without a receipt and an
// audit entry. release frees the call's usage lock once usage is recorded.
func (p *Proxy) forwardWithReceipt(w http.ResponseWriter, r *http.Request, msg message, pc policy.Call, entry audit.Entry, approvedBy string, body []byte, release func()) {
	fail := func(what string) {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse(msg.id, codeInternalError, what+"; call not forwarded"))
	}
	encoded, rcpt, err := p.receipts.Issue(receipt.Input{
		AgentID: entry.AgentID, OwnerID: entry.OwnerID, ApprovedBy: approvedBy,
		Tool: entry.Tool, ParamsHash: entry.ParamsHash, Summary: entry.Summary,
		Level: string(entry.Level), Policy: entry.Rule,
	})
	if err != nil {
		p.log.Error("receipt signing failed", "tool", entry.Tool, "err", err)
		fail("could not sign a receipt")
		return
	}
	withReceipt, err := injectReceipt(body, encoded)
	if err != nil {
		fail("could not attach the receipt")
		return
	}
	// Usage first: if the audit write then fails, a call is over-counted
	// (the safe way round) rather than forwarded uncounted. Likewise if one
	// scope's record fails after another's was saved.
	if !p.count(w, r, msg, pc, entry) {
		return
	}
	entry.Outcome = audit.OutcomeForwarded
	entry.ReceiptID = rcpt.ReceiptID
	if err := p.record(r.Context(), entry); err != nil {
		fail("audit log unavailable")
		return
	}
	release() // counted: the next call may be decided while this one runs upstream
	// The reverse proxy reads the header value from the request context.
	r = r.WithContext(context.WithValue(r.Context(), receiptKey{}, string(encoded)))
	p.forward(w, r, withReceipt)
}

// receiptKey is the context key for the receipt to send upstream.
type receiptKey struct{}

// record saves an audit entry and logs the decision. Arguments are never
// logged, only their hash and a summary of which keys were present.
func (p *Proxy) record(ctx context.Context, e audit.Entry) error {
	saved, err := p.store.AppendAudit(ctx, e)
	if err != nil {
		p.log.Error("audit write failed", "agent", e.AgentID, "tool", e.Tool, "err", err)
		return err
	}
	p.log.Info("decision", "audit_id", saved.ID, "agent", e.AgentID, "tool", e.Tool,
		"decision", e.Decision, "rule", e.Rule, "outcome", e.Outcome, "params_hash", e.ParamsHash,
		"approval_id", e.ApprovalID, "receipt_id", e.ReceiptID)
	return nil
}

func (p *Proxy) authenticate(r *http.Request) (config.Agent, bool) {
	scheme, key, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || key == "" {
		return config.Agent{}, false
	}
	agent, found := p.agents[sha256.Sum256([]byte(key))]
	return agent, found
}

// forward sends the request upstream unchanged. body is the already-read
// request body, or nil if it hasn't been read.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte) {
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}
	p.rp.ServeHTTP(w, r)
}

// newReverseProxy uses the standard library's reverse proxy, which already
// handles hop-by-hop headers and streaming responses such as SSE.
func newReverseProxy(upstream *url.URL, log *slog.Logger) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Point at the upstream's own path. (SetURL would append ours to it.)
			pr.Out.URL.Scheme = upstream.Scheme
			pr.Out.URL.Host = upstream.Host
			pr.Out.URL.Path = upstream.Path
			pr.Out.URL.RawPath = upstream.RawPath
			pr.Out.Host = upstream.Host
			// The agent's key is for us, not for the tool server.
			pr.Out.Header.Del("Authorization")
			// Only ConsequenceOS attaches receipts: drop any the agent sent,
			// then add ours if this call has one.
			pr.Out.Header.Del(headerReceipt)
			if rcpt, ok := pr.In.Context().Value(receiptKey{}).(string); ok {
				pr.Out.Header.Set(headerReceipt, rcpt)
			}
			pr.SetXForwarded()
		},
		FlushInterval: -1, // flush every write, so SSE events arrive immediately
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return // the agent hung up; nobody to answer
			}
			log.Error("upstream request failed", "err", err)
			writeJSON(w, http.StatusBadGateway, errorResponse(nil, codeInternalError, "upstream MCP server unavailable"))
		},
	}
}

// Compile-time check that *Proxy is an http.Handler.
var _ http.Handler = (*Proxy)(nil)

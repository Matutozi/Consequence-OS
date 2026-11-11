// Package proxy is Guard 1: it sits between an agent and the upstream MCP
// server, passes ordinary traffic through untouched, and runs every
// tools/call, resources/read and prompts/get past the gate first.
package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"github.com/matutozi/consequence-os/internal/consequence"
	"github.com/matutozi/consequence-os/internal/gate"
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
	// Resolver assesses each call's consequence before the policy decides.
	// nil means the engine's own, built from the tools map.
	Resolver  consequence.Resolver
	Store     store.Store
	Approvals *approval.Service
	Receipts  *receipt.Issuer
	// Receiver is the upstream's receiver ID. Set, every receipt is v1 and
	// names it, with the call's consequence; empty, receipts are v0.
	Receiver string
	Log      *slog.Logger
	Now      func() time.Time // nil means time.Now; tests pass a fixed clock
}

// Proxy implements http.Handler for the /mcp endpoint. It is the HTTP
// adapter over the gate: it authenticates agents, parses MCP messages,
// asks the gate about gated calls, words the answer, and forwards allowed
// calls with a receipt.
type Proxy struct {
	gate      *gate.Gate
	approvals *approval.Service // for the wording of held and refused calls
	receipts  *receipt.Issuer
	receiver  string
	log       *slog.Logger
	agents    map[[32]byte]config.Agent // keyed by sha256 of the API key
	origins   map[string]bool
	rp        *httputil.ReverseProxy
}

// New builds a Proxy.
func New(opts Options) (*Proxy, error) {
	upstream, err := url.Parse(opts.Upstream)
	if err != nil || upstream.Host == "" {
		return nil, fmt.Errorf("proxy: bad upstream URL %q", opts.Upstream)
	}
	if opts.Engine == nil || opts.Store == nil || opts.Approvals == nil || opts.Receipts == nil || opts.Log == nil {
		return nil, fmt.Errorf("proxy: Engine, Store, Approvals, Receipts and Log are required")
	}
	g, err := gate.New(gate.Options{
		Engine: opts.Engine, Resolver: opts.Resolver, Store: opts.Store,
		Approvals: opts.Approvals, Log: opts.Log, Now: opts.Now,
	})
	if err != nil {
		return nil, err
	}
	p := &Proxy{
		gate:      g,
		approvals: opts.Approvals,
		receipts:  opts.Receipts,
		receiver:  opts.Receiver,
		log:       opts.Log,
		agents:    make(map[[32]byte]config.Agent, len(opts.Agents)),
		origins:   make(map[string]bool, len(opts.AllowedOrigins)),
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
// path through the gate: limits, deny, ask and the audit log all apply to
// both. Only allowed tool calls get a receipt.
func (p *Proxy) handleCall(w http.ResponseWriter, r *http.Request, agent config.Agent, msg message, body []byte) {
	call, rerr := parseCall(msg)
	if rerr == nil {
		rerr = checkHeaders(r.Header, msg, &call)
	}
	if rerr != nil {
		_ = p.gate.Record(r.Context(), audit.Entry{ // best effort: nothing is forwarded either way
			AgentID: agent.ID, OwnerID: agent.OwnerID, Tool: call.name, Outcome: audit.OutcomeRejected, Detail: rerr.message,
		})
		writeJSON(w, rerr.status, errorResponse(msg.id, rerr.code, rerr.message))
		return
	}

	res, err := p.gate.Decide(r.Context(), gate.Request{
		AgentID: agent.ID, OwnerID: agent.OwnerID, Name: call.name, RawArgs: call.rawArgs, Args: call.args,
	})
	if err != nil {
		p.fail(w, msg, err)
		return
	}
	defer res.Release()

	switch res.Verdict {
	case gate.Allowed:
		p.forwardAllowed(w, r, msg, call, res, body)

	case gate.Denied:
		refuse(w, msg, call, fmt.Sprintf("Blocked by ConsequenceOS: policy rule %q does not allow %s. Do not retry this call.",
			res.Decision.Rule, call.what()))

	case gate.TooManyPending:
		refuse(w, msg, call, fmt.Sprintf("Refused by ConsequenceOS: this agent already has %d requests waiting for a human to approve, "+
			"the most allowed, so %s was not sent for approval. Do not retry it or similar calls now. "+
			"Tell the user requests are waiting for their decision, and try again after they decide.",
			p.approvals.MaxPending(), call.what()))

	case gate.Declined:
		refuse(w, msg, call, fmt.Sprintf("Rejected: an approver declined %s (approval %s). Do not retry it; tell the user it was declined.",
			call.what(), res.Approval.ID))

	default: // gate.Held
		a := res.Approval
		text := fmt.Sprintf("Approval pending: %s needs a human to approve it (policy rule %q). "+
			"Approval ID: %s. Status: %s . "+
			"Tell the user this action is waiting for approval. Once it is approved, retry this exact call "+
			"with the same arguments within %s; it will then go through once.",
			call.what(), res.Decision.Rule, a.ID, p.approvals.StatusURL(a.ID), approval.HumanDuration(p.approvals.Validity()))
		if !a.ExpiresAt.IsZero() {
			text += fmt.Sprintf(" If nobody decides by %s, the request expires.", a.ExpiresAt.Format(time.RFC3339))
		}
		refuse(w, msg, call, text)
	}
}

// fail answers a call the gate could not decide or record. Nothing is
// forwarded.
func (p *Proxy) fail(w http.ResponseWriter, msg message, err error) {
	var gerr *gate.Error
	switch {
	case errors.As(err, &gerr) && gerr.BadArguments:
		writeJSON(w, http.StatusBadRequest, errorResponse(msg.id, codeInvalidParams, gerr.What))
	case errors.As(err, &gerr):
		writeJSON(w, http.StatusServiceUnavailable, errorResponse(msg.id, codeInternalError, gerr.What+"; call not forwarded"))
	default:
		p.log.Error("gate failed", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, errorResponse(msg.id, codeInternalError, "call not forwarded"))
	}
}

// forwardAllowed forwards an allowed or approved call. Tool calls carry a
// receipt; reads don't, because receipts are for actions and receivers
// check only tools/call.
func (p *Proxy) forwardAllowed(w http.ResponseWriter, r *http.Request, msg message, call toolCall, res *gate.Result, body []byte) {
	if call.isTool() {
		p.forwardWithReceipt(w, r, msg, res, body)
		return
	}
	if err := res.Admit(r.Context(), ""); err != nil {
		p.fail(w, msg, err)
		return
	}
	p.forward(w, r, body)
}

// forwardWithReceipt signs a receipt for an allowed or approved call, has
// the gate count and audit it, and forwards the call with the receipt
// attached in both the X-Consequence-Receipt header and
// params._meta.consequenceReceipt. Any failure stops the call: nothing is
// forwarded without a receipt and an audit entry.
func (p *Proxy) forwardWithReceipt(w http.ResponseWriter, r *http.Request, msg message, res *gate.Result, body []byte) {
	fail := func(what string) {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse(msg.id, codeInternalError, what+"; call not forwarded"))
	}
	e := res.Entry
	in := receipt.Input{
		AgentID: e.AgentID, OwnerID: e.OwnerID, ApprovedBy: res.ApprovedBy,
		Tool: e.Tool, ParamsHash: e.ParamsHash, Summary: e.Summary,
		Level: string(e.Level), Policy: e.Rule,
	}
	if p.receiver != "" {
		// v1: the receipt names its receiver and says how serious the call is.
		a := res.Decision.Consequence
		in.Audience = p.receiver
		in.Consequence = &verify.Consequence{Score: a.Score, Reversibility: string(a.Reversibility), Source: a.Source, MapHash: a.MapHash}
	}
	encoded, rcpt, err := p.receipts.Issue(in)
	if err != nil {
		p.log.Error("receipt signing failed", "tool", e.Tool, "err", err)
		fail("could not sign a receipt")
		return
	}
	withReceipt, err := injectReceipt(body, encoded)
	if err != nil {
		fail("could not attach the receipt")
		return
	}
	if err := res.Admit(r.Context(), rcpt.ReceiptID); err != nil {
		p.fail(w, msg, err)
		return
	}
	// The reverse proxy reads the header value from the request context.
	r = r.WithContext(context.WithValue(r.Context(), receiptKey{}, string(encoded)))
	p.forward(w, r, withReceipt)
}

// receiptKey is the context key for the receipt to send upstream.
type receiptKey struct{}

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

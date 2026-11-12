package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"sync"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/gate"
	"github.com/matutozi/consequence-os/internal/toolpin"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// The stdio wrapper is the HTTP proxy's twin for local MCP servers, which
// an agent starts as a child process and talks to over stdin and stdout,
// one JSON-RPC message per line. The agent starts consequenced -stdio
// instead; it starts the real server and relays messages both ways,
// running tools/call, resources/read and prompts/get past the gate. It
// parses messages exactly as the proxy does.
//
// There are no receipts: the server is a local process the person chose
// to run, not a receiver. Any receipt the agent puts in a call is removed.

// StdioOptions configures RunStdio.
type StdioOptions struct {
	Command []string // the MCP server to start, and its arguments
	Env     []string // the server's whole environment
	// Stderr gets the server's stderr. If Log writes to the same place,
	// it must be safe to write from two goroutines at once.
	Stderr  io.Writer
	AgentID string
	OwnerID string
	// Open opens the gate for one call, with the approval service it holds
	// asked calls in, and returns the function that closes both. RunStdio
	// opens it for each call rather than once, so other processes can use
	// the same state_dir between calls: consequenced -approve, or another
	// wrapper for another server.
	Open func(ctx context.Context) (*gate.Gate, *approval.Service, func(), error)
	// OpenTools opens the pins of this server's tool definitions for one
	// tools/list answer, and returns the function that closes them. nil
	// passes listings through unchecked. The gate Open returns checks
	// calls against the same pins.
	OpenTools func(ctx context.Context) (*toolpin.Service, func(), error)
	// ApproveCommand is the command a person runs to approve a held call.
	ApproveCommand func(approvalID string) string
	// AskInClient asks the person through the MCP client about held calls,
	// when the client can show forms; see stdio_ask.go. It trusts the
	// client to show the question to a person, so it's off by default.
	AskInClient bool
	// LocalUser names the person in decisions made in the client, e.g.
	// "local:ada".
	LocalUser string
	Log       *slog.Logger
}

// ErrServerExited means the MCP server stopped before the client did.
var ErrServerExited = errors.New("the MCP server exited")

// RunStdio relays messages between the client on in and out and the
// server it starts, until the client closes in, the server exits, or ctx
// is cancelled. When the server exits first, every request still waiting
// for it is answered with an error, and RunStdio returns ErrServerExited.
func RunStdio(ctx context.Context, in io.Reader, out io.Writer, opts StdioOptions) error {
	if len(opts.Command) == 0 {
		return errors.New("stdio: no server command; put it after --")
	}
	if opts.Open == nil || opts.ApproveCommand == nil || opts.Log == nil {
		return errors.New("stdio: Open, ApproveCommand and Log are required")
	}
	cmd := exec.CommandContext(ctx, opts.Command[0], opts.Command[1:]...)
	cmd.Env = opts.Env
	cmd.Stderr = opts.Stderr
	cmd.WaitDelay = 5 * time.Second // after the kill, don't wait forever for its pipes
	toServer, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	fromServer, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("stdio: start %s: %w", opts.Command[0], err)
	}
	s := &stdio{opts: opts, client: &lineWriter{w: out}, server: toServer, waiting: map[string]string{}, listings: map[string]json.RawMessage{}, askKey: newAskKey()}

	serverDone := make(chan struct{})
	go func() {
		s.relayFromServer(fromServer)
		close(serverDone)
	}()
	clientDone := make(chan error, 1)
	go func() { clientDone <- s.relayFromClient(ctx, in) }()

	select {
	case <-serverDone:
		waitErr := cmd.Wait()
		s.answerWaiting("the MCP server exited before answering; the call may or may not have run")
		opts.Log.Error("the MCP server exited", "err", waitErr)
		return ErrServerExited
	case err := <-clientDone:
		// The client is done: let the server finish and exit by itself.
		_ = toServer.Close()
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return err
	case <-ctx.Done():
		_ = cmd.Wait() // CommandContext kills the server
		return ctx.Err()
	}
}

type stdio struct {
	opts     StdioOptions
	client   *lineWriter
	server   io.Writer // the server's stdin; written under serverMu
	serverMu sync.Mutex
	askKey   []byte // signs the requestState of questions asked in the client

	mu      sync.Mutex
	waiting map[string]string // IDs of requests sent to the server and not yet answered, and their methods
	// listings holds the tools/list requests not yet answered: each ID in
	// canonical form (listingID), and as the client sent it.
	listings map[string]json.RawMessage
}

// lineWriter writes whole lines, one writer at a time: our answers and the
// server's messages share the client's stdout.
type lineWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lineWriter) writeLine(line []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.w.Write(append(bytes.TrimRight(line, "\r\n"), '\n'))
	return err
}

func (l *lineWriter) writeJSON(v any) {
	line, err := marshalRaw(v)
	if err == nil {
		_ = l.writeLine(line)
	}
}

// relayFromServer copies the server's messages to the client, noting each
// answer to a request that was waiting, and checking tool listings and the
// server's requests of the client (serverreq.go).
func (s *stdio) relayFromServer(r io.Reader) {
	br := bufio.NewReader(r)
	check := serverCheck{open: s.openGate, agentID: s.opts.AgentID, ownerID: s.opts.OwnerID, reservedKey: askKey, log: s.opts.Log}
	for {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 && s.unreadableWhileListing(line) {
			line = nil // dropped; every listing waiting was answered with an error
		}
		if len(bytes.TrimSpace(line)) > 0 {
			method := ""
			if id, ok := responseID(line); ok {
				key, _ := listingID(json.RawMessage(id))
				s.mu.Lock()
				method = s.waiting[id]
				delete(s.waiting, id)
				_, isListing := s.listings[key]
				delete(s.listings, key)
				s.mu.Unlock()
				if isListing {
					line = s.checkListing(json.RawMessage(id), line)
				}
			}
			out, keep, answer := check.message(context.Background(), bytes.TrimSpace(line), func(json.RawMessage) string { return method })
			if answer != nil {
				_ = s.writeServer(answer)
			}
			if keep {
				_ = s.client.writeLine(out)
			}
		}
		if err != nil {
			return
		}
	}
}

// unreadableWhileListing reports whether line is not strict JSON while a
// tools/list waits for its answer. Such a line can't be matched to an ID,
// yet a lenient client might read it as the listing (Python's json accepts
// NaN, say), so it is dropped, and each listing waiting is answered with
// an error rather than left to hang.
func (s *stdio) unreadableWhileListing(line []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.listings) == 0 {
		return false
	}
	if _, err := verify.Canonicalize(bytes.TrimSpace(line)); err == nil {
		return false
	}
	s.opts.Log.Error("dropped a message from the server that isn't strict JSON, while a tool list was waiting; the list wasn't passed on")
	for key, id := range s.listings {
		s.client.writeJSON(errorResponse(id, codeInternalError, errUncheckedListing.Error()))
		delete(s.listings, key)
		delete(s.waiting, string(id))
	}
	return true
}

// checkListing returns the answer to a tools/list with its tools checked
// against their pins, or an error answer when they couldn't be.
func (s *stdio) checkListing(id json.RawMessage, line []byte) []byte {
	ctx := context.Background()
	tools, closeTools, err := s.opts.OpenTools(ctx)
	if err == nil {
		defer closeTools()
		var out []byte
		if out, err = filterListing(ctx, tools, toolpin.Lister{AgentID: s.opts.AgentID, OwnerID: s.opts.OwnerID}, line); err == nil {
			return out
		}
	}
	s.opts.Log.Error("tool list not passed on", "err", err)
	answer, _ := marshalRaw(errorResponse(id, codeInternalError, errUncheckedListing.Error()))
	return answer
}

// responseID returns the ID of a JSON-RPC response, or ok=false for a
// request or notification.
func responseID(line []byte) (string, bool) {
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method *string         `json:"method"`
	}
	if json.Unmarshal(line, &m) != nil || m.Method != nil || len(m.ID) == 0 {
		return "", false
	}
	return string(m.ID), true
}

// answerWaiting answers every request the server never answered.
func (s *stdio) answerWaiting(why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.waiting {
		s.client.writeJSON(errorResponse(json.RawMessage(id), codeInternalError, why))
		delete(s.waiting, id)
	}
}

// relayFromClient reads the client's messages, one per line, and sends
// each on to the server or answers it, until the client closes stdin.
func (s *stdio) relayFromClient(ctx context.Context, r io.Reader) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, tooLong, err := readLine(br, maxBodyBytes)
		if tooLong {
			s.client.writeJSON(errorResponse(nil, codeInvalidRequest, "message too large"))
		} else if len(bytes.TrimSpace(line)) > 0 {
			if ferr := s.handle(ctx, line); ferr != nil {
				return ferr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// readLine reads one line, without its line break. A line longer than max
// is read to its end and dropped, with tooLong set.
func readLine(br *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	for {
		chunk, err := br.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > max+1 { // +1 for the line break
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return bytes.TrimRight(line, "\r\n"), tooLong, err
	}
}

// handle deals with one message from the client. Only a failure to write
// to the server is returned: it means the server is gone.
func (s *stdio) handle(ctx context.Context, line []byte) (err error) {
	msg, rerr := parseMessage(line)
	if rerr != nil {
		s.client.writeJSON(errorResponse(nil, rerr.code, rerr.message))
		return nil
	}
	if !gated(msg.method) {
		return s.forward(msg, line)
	}
	defer func() {
		if r := recover(); r != nil {
			s.opts.Log.Error("stdio: internal error", "panic", r)
			s.client.writeJSON(errorResponse(msg.id, codeInternalError, "internal error; call not forwarded"))
			err = nil
		}
	}()
	return s.handleCall(ctx, msg, line)
}

// forward sends a message to the server as it came, noting requests that
// will need an answer. A request is noted before it is sent, so its answer
// can't arrive first.
func (s *stdio) forward(msg message, line []byte) error {
	if msg.method != "" && len(msg.id) > 0 {
		s.mu.Lock()
		s.waiting[string(msg.id)] = msg.method
		if key, ok := listingID(msg.id); ok && msg.method == methodToolsList && s.opts.OpenTools != nil {
			s.listings[key] = msg.id
		}
		s.mu.Unlock()
	}
	return s.writeServer(line)
}

// writeServer sends one line to the server. The client's messages and our
// answers to the server's refused requests take turns.
func (s *stdio) writeServer(line []byte) error {
	s.serverMu.Lock()
	defer s.serverMu.Unlock()
	if _, err := s.server.Write(append(append([]byte(nil), line...), '\n')); err != nil {
		return fmt.Errorf("%w: %v", ErrServerExited, err)
	}
	return nil
}

// openGate opens the gate for one server request, as for a call.
func (s *stdio) openGate(ctx context.Context) (*gate.Gate, func(), error) {
	g, _, closeGate, err := s.opts.Open(ctx)
	return g, closeGate, err
}

// handleCall runs one gated call past the gate, as the HTTP proxy does.
func (s *stdio) handleCall(ctx context.Context, msg message, line []byte) error {
	call, rerr := parseCall(msg)
	g, approvals, closeGate, err := s.opts.Open(ctx)
	if err != nil {
		s.opts.Log.Error("stdio: the state_dir can't be opened", "err", err)
		s.client.writeJSON(errorResponse(msg.id, codeInternalError, "the policy's state can't be opened just now; call not forwarded"))
		return nil
	}
	defer closeGate()
	if rerr != nil {
		_ = g.Record(ctx, audit.Entry{AgentID: s.opts.AgentID, OwnerID: s.opts.OwnerID, Tool: call.name, Outcome: audit.OutcomeRejected, Detail: rerr.message})
		s.client.writeJSON(errorResponse(msg.id, rerr.code, rerr.message))
		return nil
	}

	// A retry that answers our question decides its approval first, so
	// the gate then finds it decided.
	dismissedIt := s.applyAnswer(ctx, approvals, msg, call)
	ours := s.carriesOurState(msg)

	res, err := g.Decide(ctx, gate.Request{AgentID: s.opts.AgentID, OwnerID: s.opts.OwnerID, Name: call.name, RawArgs: call.rawArgs, Args: call.args})
	if err != nil {
		var gerr *gate.Error
		code, what := codeInternalError, "call not forwarded"
		if errors.As(err, &gerr) {
			what = gerr.What + "; call not forwarded"
			if gerr.BadArguments {
				code, what = codeInvalidParams, gerr.What
			}
		}
		s.client.writeJSON(errorResponse(msg.id, code, what))
		return nil
	}
	defer res.Release()

	switch res.Verdict {
	case gate.Allowed:
		forwardLine, err := stripReceipt(line)
		if err == nil {
			forwardLine, err = withoutOurInput(forwardLine, ours)
		}
		if err != nil {
			s.client.writeJSON(errorResponse(msg.id, codeInvalidParams, "params._meta must be an object"))
			return nil
		}
		if err := res.Admit(ctx, ""); err != nil {
			s.client.writeJSON(errorResponse(msg.id, codeInternalError, unavailableText(err)))
			return nil
		}
		closeGate() // counted and recorded: free the state_dir before the server runs the call
		return s.forward(msg, forwardLine)
	case gate.Denied:
		s.client.writeJSON(refusal(msg, call, fmt.Sprintf("Blocked by ConsequenceOS: policy rule %q does not allow %s. Do not retry this call.", res.Decision.Rule, call.what())))
	case gate.TooManyPending:
		s.client.writeJSON(refusal(msg, call, fmt.Sprintf("Refused by ConsequenceOS: this agent already has %d requests waiting for a human to approve, "+
			"the most allowed, so %s was not sent for approval. Do not retry it or similar calls now. "+
			"Tell the user requests are waiting for their decision, and try again after they decide.", approvals.MaxPending(), call.what())))
	case gate.Declined:
		s.client.writeJSON(refusal(msg, call, fmt.Sprintf("Rejected: the user declined %s (approval %s). Do not retry it; tell the user it was declined.", call.what(), res.Approval.ID)))
	case gate.Invalid:
		s.client.writeJSON(refusal(msg, call, invalidText(res)))
	default: // gate.Held
		if !dismissedIt && s.askInClient(msg, call, res) {
			return nil
		}
		a := res.Approval
		text := fmt.Sprintf("Approval pending: %s needs the user to approve it (policy rule %q). Approval ID: %s. "+
			"Tell the user this action is waiting for them, and that they approve it by running `%s` in a terminal. "+
			"Once it is approved, retry this exact call with the same arguments within %s; it will then go through once.",
			call.what(), res.Decision.Rule, a.ID, s.opts.ApproveCommand(a.ID), approval.HumanDuration(approvals.Validity()))
		if !a.ExpiresAt.IsZero() {
			text += fmt.Sprintf(" If nobody decides by %s, the request expires.", a.ExpiresAt.Format(time.RFC3339))
		}
		text += changedText(res, call)
		s.client.writeJSON(refusal(msg, call, text))
	}
	return nil
}

func unavailableText(err error) string {
	var gerr *gate.Error
	if errors.As(err, &gerr) {
		return gerr.What + "; call not forwarded"
	}
	return "call not forwarded"
}

// stripReceipt removes params._meta.consequenceReceipt, which only
// ConsequenceOS may set, and returns line unchanged when there is none.
func stripReceipt(line []byte) ([]byte, error) {
	var top, params, meta map[string]json.RawMessage
	if err := json.Unmarshal(line, &top); err != nil {
		return nil, err
	}
	if json.Unmarshal(top["params"], &params) != nil {
		return line, nil
	}
	raw, ok := params["_meta"]
	if !ok || string(raw) == "null" {
		return line, nil
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, err
	}
	if _, ok := meta[verify.MetaKey]; !ok {
		return line, nil
	}
	delete(meta, verify.MetaKey)
	var err error
	if params["_meta"], err = marshalRaw(meta); err != nil {
		return nil, err
	}
	if top["params"], err = marshalRaw(params); err != nil {
		return nil, err
	}
	return marshalRaw(top)
}

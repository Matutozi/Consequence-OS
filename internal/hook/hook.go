// Package hook runs ConsequenceOS as a Claude Code PreToolUse hook. Claude
// Code runs `consequenced -hook claude-code` before each tool call, with
// the call as JSON on stdin, and reads the decision from stdout. The hook
// is an adapter over the gate, as the HTTP proxy is.
//
// ConsequenceOS can only make a call stricter. A denied call gets a deny,
// which Claude reads. An asked call gets an ask, so Claude Code asks the
// person at the keyboard. An allowed call gets no decision at all, so
// Claude Code's own permission settings still apply.
//
// Claude Code lets a tool call run when a hook fails in most ways: a
// crash, an odd exit code, output it can't read. Only exit code 2 always
// blocks. So every failure here, a panic included, exits 2 with the reason
// on stderr.
package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/matutozi/consequence-os/internal/config"
	"github.com/matutozi/consequence-os/internal/gate"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/store"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// Exit codes. Claude Code blocks the call on ExitBlock whatever stdout says.
const (
	ExitOK    = 0
	ExitBlock = 2
)

// DefaultLockTimeout is how long a hook waits for the state_dir. Claude
// Code runs tool calls in parallel, and each hook takes the lock in turn.
const DefaultLockTimeout = 10 * time.Second

// maxInput caps the call read from stdin. A Write carries a whole file.
const maxInput = 64 << 20

// ProjectDirEnv is where Claude Code puts the project's root directory.
const ProjectDirEnv = "CLAUDE_PROJECT_DIR"

// Options configures Run.
type Options struct {
	ConfigPath  string
	LookupEnv   config.LookupEnv // os.LookupEnv outside tests
	Now         func() time.Time // nil means time.Now
	LockTimeout time.Duration    // 0 means DefaultLockTimeout
}

// input is what Claude Code sends a PreToolUse hook. Fields it adds later
// are ignored.
type input struct {
	HookEventName string          `json:"hook_event_name"`
	SessionID     string          `json:"session_id"`
	Cwd           string          `json:"cwd"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
}

// output is the decision a PreToolUse hook prints.
type output struct {
	HookSpecificOutput decision `json:"hookSpecificOutput"`
}

type decision struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"` // "deny" or "ask"; ConsequenceOS never sends "allow"
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// blocked is a failure that stops the call. Its message is shown to Claude.
type blocked struct{ reason string }

func (b *blocked) Error() string { return b.reason }

func block(format string, args ...any) error {
	return &blocked{reason: "ConsequenceOS blocked this call: " + fmt.Sprintf(format, args...)}
}

// Run decides one call: it reads it from in, writes the decision to out,
// and returns the exit code for the process. Failures go to errOut with
// ExitBlock.
func Run(ctx context.Context, in io.Reader, out, errOut io.Writer, opts Options) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(errOut, "ConsequenceOS blocked this call: internal error: %v\n", r)
			code = ExitBlock
		}
	}()
	answer, err := run(ctx, in, errOut, opts)
	if err == nil && answer != nil {
		err = writeJSON(out, answer)
	}
	if err != nil {
		var b *blocked
		if !errors.As(err, &b) {
			b = &blocked{reason: "ConsequenceOS blocked this call: " + err.Error()}
		}
		fmt.Fprintln(errOut, b.reason)
		return ExitBlock
	}
	return ExitOK
}

// run returns the decision to print, or nil to let Claude Code decide.
func run(ctx context.Context, in io.Reader, errOut io.Writer, opts Options) (*output, error) {
	if opts.LookupEnv == nil {
		return nil, errors.New("hook: Options.LookupEnv is required")
	}
	call, args, err := readInput(in)
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadLocal(opts.ConfigPath, opts.LookupEnv)
	if err != nil {
		return nil, block("the config can't be loaded: %v", err)
	}
	engine, err := cfg.NewEngine()
	if err != nil {
		return nil, block("the policy can't be built: %v", err)
	}
	// Warnings and errors only: a line per call would bury what matters.
	log := slog.New(slog.NewTextHandler(errOut, &slog.HandlerOptions{Level: slog.LevelWarn}))
	timeout := opts.LockTimeout
	if timeout == 0 {
		timeout = DefaultLockTimeout
	}
	st, err := store.OpenFile(cfg.StateDir, store.FileOptions{Log: log, LockTimeout: timeout})
	if err != nil {
		return nil, block("the state_dir can't be opened: %v", err)
	}
	defer st.Close()
	g, err := gate.New(gate.Options{Engine: engine, Store: st, Observe: cfg.Observe(), Log: log, Now: opts.Now}) // no approvals: the person is at the keyboard
	if err != nil {
		return nil, err
	}

	project, ok := opts.LookupEnv(ProjectDirEnv)
	if !ok || project == "" {
		project = call.Cwd
	}
	derive(call.ToolName, args, call.Cwd, project)

	res, err := g.Decide(ctx, gate.Request{
		AgentID: cfg.LocalAgent.ID, OwnerID: cfg.LocalAgent.OwnerID,
		Name: call.ToolName, RawArgs: call.ToolInput, Args: args,
	})
	if err != nil {
		return nil, block("%v", unavailable(err))
	}
	defer res.Release()

	d := res.Decision
	switch res.Verdict {
	case gate.Allowed:
		res.Entry.Detail = "let through to Claude Code"
		if err := res.Admit(ctx, ""); err != nil {
			return nil, block("%v", unavailable(err))
		}
		return nil, nil
	case gate.AskUser:
		res.Entry.Detail = "asked the user in Claude Code"
		if err := res.Admit(ctx, ""); err != nil {
			return nil, block("%v", unavailable(err))
		}
		return answer("ask", askReason(call.ToolName, d)), nil
	case gate.Denied:
		return answer("deny", fmt.Sprintf("Blocked by ConsequenceOS: policy rule %q does not allow this %s call. "+
			"Do not retry it or try to get the same result another way; tell the user it was blocked.", d.Rule, call.ToolName)), nil
	}
	// Held, Declined and TooManyPending need an approval service, which the hook doesn't have.
	return nil, fmt.Errorf("unexpected verdict %d", res.Verdict)
}

// readInput reads and checks the call. It refuses what the HTTP proxy
// refuses: duplicate or case-variant keys, and tool names that pose as
// resource or prompt reads.
func readInput(in io.Reader) (input, map[string]any, error) {
	body, err := io.ReadAll(io.LimitReader(in, maxInput+1))
	if err != nil {
		return input{}, nil, block("its input can't be read: %v", err)
	}
	if len(body) > maxInput {
		return input{}, nil, block("its input is over %d MiB", maxInput>>20)
	}
	if err := verify.CheckUnambiguous(body); err != nil {
		return input{}, nil, block("its input is ambiguous or not JSON: %v", err)
	}
	var call input
	if err := json.Unmarshal(body, &call); err != nil {
		return input{}, nil, block("its input is not a hook call: %v", err)
	}
	switch {
	case call.HookEventName != "PreToolUse":
		return input{}, nil, block("the hook runs only on PreToolUse, not %q; check the hooks in Claude Code's settings", call.HookEventName)
	case call.ToolName == "":
		return input{}, nil, block("the call names no tool")
	case policy.IsRead(call.ToolName):
		return input{}, nil, block("tool names may not start with resource:, prompt: or server:")
	case call.Cwd == "":
		return input{}, nil, block("the call has no working directory")
	}
	var args map[string]any
	if raw := bytes.TrimSpace(call.ToolInput); len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &args); err != nil {
			return input{}, nil, block("tool_input must be a JSON object")
		}
	}
	if args == nil {
		args = map[string]any{}
	}
	return call, args, nil
}

// unavailable words a gate error for Claude: what failed, not the cause.
func unavailable(err error) string {
	var gerr *gate.Error
	if errors.As(err, &gerr) {
		return gerr.What
	}
	return err.Error()
}

func answer(permission, reason string) *output {
	return &output{decision{HookEventName: "PreToolUse", PermissionDecision: permission, PermissionDecisionReason: reason}}
}

// askReason is shown to the person in Claude Code's permission prompt.
func askReason(tool string, d policy.Decision) string {
	var b strings.Builder
	if d.Rule == policy.DefaultRule {
		fmt.Fprintf(&b, "ConsequenceOS: no rule covers this %s call, and it scores %d of 100, so it needs your approval.", tool, d.Consequence.Score)
	} else {
		fmt.Fprintf(&b, "ConsequenceOS: policy rule %q asks you to approve this %s call (consequence score %d of 100).", d.Rule, tool, d.Consequence.Score)
	}
	for _, r := range d.Consequence.Reasons {
		b.WriteString(" " + r)
	}
	return b.String()
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// Warnings points out rules that are risky in the hook mode. One for now:
// an allow rule covering Bash that doesn't require compound: false. That
// rule lets "git status; rm -rf ~" through as if it were "git status".
func Warnings(rules []policy.Rule) []string {
	var warnings []string
	for _, r := range rules {
		if r.Action != policy.ActionAllow || !coversShell(r.Tool) || requiresSimple(r.When) {
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"rule %q allows shell commands without requiring compound: false, so \"git status; rm -rf ~\" passes as \"git status\". "+
				"Add { arg: compound, op: eq, value: false } to its conditions.", r.Name))
	}
	return warnings
}

func coversShell(pattern string) bool {
	for tool := range shellTools {
		if policy.MatchTool(pattern, tool) {
			return true
		}
	}
	return false
}

// requiresSimple reports whether the conditions include compound eq false.
func requiresSimple(conds policy.Conditions) bool {
	for _, c := range conds {
		if c.Arg == ArgCompound && c.Op == policy.OpEq && c.Value == false {
			return true
		}
	}
	return false
}

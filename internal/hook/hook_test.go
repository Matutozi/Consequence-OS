package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/config"
	"github.com/matutozi/consequence-os/internal/store"
)

// testPolicy is close to the starter policy P.4 will write.
const testPolicy = `
state_dir: STATE
local_agent: { id: claude-code, owner_id: ada }
tools: { Read: read, Grep: read, Glob: read, Edit: reversible, Write: reversible, Bash: irreversible }
rules:
  - name: guard-the-guard
    tool: "*"
    when: { arg: file_path, op: like, value: ["*/.claude/settings*.json", "STATE/*"] }
    action: deny
  - name: no-secrets
    tool: "*"
    when: { arg: file_path, op: like, value: ["*/.env", "*/.env.*"], fold: true }
    action: deny
  - name: writes-through-links
    tool: "*"
    when: { arg: via_symlink, op: eq, value: true }
    action: ask
  - name: edits-in-project
    tool: Edit
    when: { arg: in_project, op: eq, value: true }
    action: allow
  - name: safe-git
    tool: Bash
    when:
      - { arg: command, op: like, value: ["git status*", "git diff*", "git log*"] }
      - { arg: compound, op: eq, value: false }
    action: allow
  - name: shell
    tool: Bash
    action: ask
`

type env struct {
	project, state, config string
	lookup                 config.LookupEnv
}

func newEnv(t *testing.T) env {
	t.Helper()
	root := t.TempDir()
	e := env{project: filepath.Join(root, "project"), state: filepath.Join(root, "state"), config: filepath.Join(root, "claude-code.yaml")}
	if err := os.MkdirAll(filepath.Join(e.project, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.config, []byte(strings.ReplaceAll(testPolicy, "STATE", e.state)), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"HOME": root, ProjectDirEnv: e.project}
	e.lookup = func(k string) (string, bool) { v, ok := vars[k]; return v, ok }
	return e
}

// call builds a PreToolUse input the way Claude Code sends it.
func (e env) call(tool, toolInput string) string {
	return `{"session_id":"abc123","transcript_path":"/x/t.jsonl","cwd":"` + e.project + `","permission_mode":"default",` +
		`"hook_event_name":"PreToolUse","tool_name":"` + tool + `","tool_input":` + toolInput + `,"tool_use_id":"toolu_01"}`
}

type result struct {
	code           int
	stdout, stderr string
}

func (e env) run(t *testing.T, stdin string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), strings.NewReader(stdin), &out, &errOut, Options{
		ConfigPath: e.config, LookupEnv: e.lookup, LockTimeout: time.Second,
		Now: func() time.Time { return time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC) },
	})
	return result{code, out.String(), errOut.String()}
}

// decision reads what Claude Code would: "" for no decision, else deny or ask.
func (r result) decision(t *testing.T) (permission, reason string) {
	t.Helper()
	if strings.TrimSpace(r.stdout) == "" {
		return "", ""
	}
	var o output
	if err := json.Unmarshal([]byte(r.stdout), &o); err != nil {
		t.Fatalf("stdout is not a hook decision: %q", r.stdout)
	}
	return o.HookSpecificOutput.PermissionDecision, o.HookSpecificOutput.PermissionDecisionReason
}

func quote(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestDecisions(t *testing.T) {
	e := newEnv(t)
	if err := os.WriteFile(filepath.Join(e.project, "real.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(e.project, "real.txt"), filepath.Join(e.project, "link.txt")); err != nil {
		t.Fatal(err)
	}
	p := func(rel string) string { return quote(filepath.Join(e.project, rel)) }
	tests := []struct {
		name, tool, input string
		want              string // "" (no decision), "ask" or "deny"
		wantRule          string // in the reason, when there is one
	}{
		{"a read in the project", "Read", `{"file_path":` + p("main.go") + `}`, "", ""},
		{"a safe git command", "Bash", `{"command":"git status --short","description":"Show status"}`, "", ""},
		{"a variable before the command", "Bash", `{"command":"GIT_PAGER=cat git log -5"}`, "ask", "shell"}, // program-level rules see git, but the command text doesn't start with git
		{"a compound command", "Bash", `{"command":"git status; rm -rf ~"}`, "ask", "shell"},
		{"a pipe", "Bash", `{"command":"git log | sh"}`, "ask", "shell"},
		{"a substitution", "Bash", `{"command":"git log $(rm -rf ~)"}`, "ask", "shell"},
		{"a force push", "Bash", `{"command":"git push --force"}`, "ask", "shell"},
		{"compound sent by the agent is replaced", "Bash", `{"command":"git status && rm -rf ~","compound":false}`, "ask", "shell"},
		{"in another case too", "Bash", `{"command":"git status && rm -rf ~","Compound":false}`, "ask", "shell"},
		{"writing .env", "Write", `{"file_path":` + p(".env") + `,"content":"SECRET=1"}`, "deny", "no-secrets"},
		{"reading .env.local", "Read", `{"file_path":` + p(".env.LOCAL") + `}`, "deny", "no-secrets"},
		{"a path with .. is resolved first", "Edit", `{"file_path":` + quote(e.project+"/sub/../.env") + `,"old_string":"a","new_string":"b"}`, "deny", "no-secrets"},
		{"a relative path is resolved against cwd", "Edit", `{"file_path":"sub/../.env","old_string":"a","new_string":"b"}`, "deny", "no-secrets"},
		{"editing Claude Code's settings", "Edit", `{"file_path":` + p(".claude/settings.local.json") + `,"old_string":"a","new_string":"b"}`, "deny", "guard-the-guard"},
		{"writing the state_dir", "Write", `{"file_path":` + quote(filepath.Join(e.state, "journal.jsonl")) + `,"content":""}`, "deny", "guard-the-guard"},
		{"an edit in the project", "Edit", `{"file_path":` + p("main.go") + `,"old_string":"a","new_string":"b"}`, "", ""},
		{"an edit through a symlink", "Edit", `{"file_path":` + p("link.txt") + `,"old_string":"a","new_string":"b"}`, "ask", "writes-through-links"},
		{"an edit outside the project", "Edit", `{"file_path":"/etc/hosts","old_string":"a","new_string":"b"}`, "ask", "default"},
		{"an edit with no path", "Edit", `{"old_string":"a","new_string":"b"}`, "ask", "writes-through-links"},
		{"an unknown MCP tool", "mcp__github__merge_pull_request", `{"repo":"acme/api","number":7}`, "ask", "default"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := e.run(t, e.call(tt.tool, tt.input))
			if r.code != ExitOK {
				t.Fatalf("exit %d: %s", r.code, r.stderr)
			}
			got, reason := r.decision(t)
			if got != tt.want {
				t.Fatalf("decision %q (%s), want %q", got, reason, tt.want)
			}
			if tt.want == "" {
				return
			}
			wantRule := `"` + tt.wantRule + `"`
			if tt.wantRule == "default" {
				wantRule = "no rule covers this"
			}
			if !strings.Contains(reason, wantRule) {
				t.Errorf("reason %q doesn't name %s", reason, wantRule)
			}
		})
	}
}

// The exact output, pinned: Claude Code reads these field names.
func TestOutputFormat(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, e.call("Write", `{"file_path":`+quote(filepath.Join(e.project, ".env"))+`,"content":"x"}`))
	want := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":` +
		`"Blocked by ConsequenceOS: policy rule \"no-secrets\" does not allow this Write call. ` +
		`Do not retry it or try to get the same result another way; tell the user it was blocked."}}` + "\n"
	if r.stdout != want {
		t.Errorf("deny:\n got %s\nwant %s", r.stdout, want)
	}
	r = e.run(t, e.call("Bash", `{"command":"make deploy"}`))
	want = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":` +
		`"ConsequenceOS: policy rule \"shell\" asks you to approve this Bash call (consequence score 80 of 100). ` +
		`Bash is listed as irreversible in the tools map."}}` + "\n"
	if r.stdout != want {
		t.Errorf("ask:\n got %s\nwant %s", r.stdout, want)
	}
}

func TestEveryCallIsAudited(t *testing.T) {
	e := newEnv(t)
	e.run(t, e.call("Read", `{"file_path":`+quote(filepath.Join(e.project, "a.go"))+`}`))
	e.run(t, e.call("Bash", `{"command":"make deploy"}`))
	e.run(t, e.call("Write", `{"file_path":`+quote(filepath.Join(e.project, ".env"))+`,"content":"API_KEY=sk-live-123"}`))

	st, err := store.OpenFile(e.state, store.FileOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	r, err := audit.VerifyChain(context.Background(), st)
	if err != nil || !r.Intact || r.Checked != 3 {
		t.Fatalf("chain = %+v, %v", r, err)
	}
	entries, _ := st.ListAudit(context.Background(), audit.Filter{})
	want := []struct {
		tool    string
		outcome audit.Outcome
		detail  string
	}{ // newest first
		{"Write", audit.OutcomeBlocked, ""},
		{"Bash", audit.OutcomeAskedUser, "asked the user in Claude Code"},
		{"Read", audit.OutcomeForwarded, "let through to Claude Code"},
	}
	for i, w := range want {
		if e := entries[i]; e.Tool != w.tool || e.Outcome != w.outcome || e.Detail != w.detail || e.AgentID != "claude-code" || e.OwnerID != "ada" {
			t.Errorf("entry %d = %+v, want %+v", i, e, w)
		}
	}
	journal, _ := os.ReadFile(filepath.Join(e.state, "journal.jsonl"))
	if bytes.Contains(journal, []byte("sk-live-123")) {
		t.Error("the journal holds a file's contents; it should hold only their hash")
	}
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("boom") }

func TestFailuresBlock(t *testing.T) {
	e := newEnv(t)
	good := e.call("Read", `{"file_path":"/x"}`)
	tests := []struct {
		name  string
		stdin string
		edit  func(*Options)
		want  string
	}{
		{"not JSON", "hello", nil, "not JSON"},
		{"duplicate keys", strings.Replace(good, `{"file_path":"/x"}`, `{"file_path":"/x","file_path":"/y"}`, 1), nil, "ambiguous"},
		{"another hook event", strings.Replace(good, "PreToolUse", "PostToolUse", 1), nil, `not "PostToolUse"`},
		{"no tool", strings.Replace(good, `"tool_name":"Read"`, `"tool_name":""`, 1), nil, "names no tool"},
		{"a tool posing as a read", strings.Replace(good, `"tool_name":"Read"`, `"tool_name":"resource:x"`, 1), nil, "resource: or prompt:"},
		{"tool_input not an object", strings.Replace(good, `{"file_path":"/x"}`, `[1]`, 1), nil, "must be a JSON object"},
		{"no config", good, func(o *Options) { o.ConfigPath = "/does/not/exist.yaml" }, "config can't be loaded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := Options{ConfigPath: e.config, LookupEnv: e.lookup, LockTimeout: time.Second}
			if tt.edit != nil {
				tt.edit(&opts)
			}
			var out, errOut bytes.Buffer
			code := Run(context.Background(), strings.NewReader(tt.stdin), &out, &errOut, opts)
			if code != ExitBlock || !strings.Contains(errOut.String(), tt.want) || !strings.HasPrefix(errOut.String(), "ConsequenceOS blocked this call") {
				t.Errorf("exit %d, stderr %q; want exit 2 and %q", code, errOut.String(), tt.want)
			}
		})
	}

	t.Run("a panic", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), panicReader{}, &out, &errOut, Options{ConfigPath: e.config, LookupEnv: e.lookup}); code != ExitBlock {
			t.Errorf("exit %d, want 2", code)
		}
		if !strings.Contains(errOut.String(), "internal error: boom") {
			t.Errorf("stderr %q", errOut.String())
		}
	})

	t.Run("state_dir held by another process", func(t *testing.T) {
		st, err := store.OpenFile(e.state, store.FileOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		var out, errOut bytes.Buffer
		code := Run(context.Background(), strings.NewReader(good), &out, &errOut,
			Options{ConfigPath: e.config, LookupEnv: e.lookup, LockTimeout: 50 * time.Millisecond})
		if code != ExitBlock || !strings.Contains(errOut.String(), "state_dir can't be opened") {
			t.Errorf("exit %d, stderr %q", code, errOut.String())
		}
	})
}

func TestShellFacts(t *testing.T) {
	tests := []struct {
		cmd, program string
		compound     bool
	}{
		{"git status", "git", false},
		{"  ls -la ", "ls", false},
		{"FOO=1 BAR=x npm test", "npm", false},
		{"FOO=1", "", false},
		{"", "", false},
		{"echo hi > out.txt", "echo", true},
		{"cat < in", "cat", true},
		{"a && b", "a", true},
		{"a || b", "a", true},
		{"a & b", "a", true},
		{"a\nb", "a", true},
		{"(cd x; rm y)", "(cd", true},
		{"echo `id`", "echo", true},
		{`"git" push`, `"git"`, false}, // a quoted program names nothing an allow-list would list
	}
	for _, tt := range tests {
		program, compound := shellFacts(tt.cmd)
		if program != tt.program || compound != tt.compound {
			t.Errorf("shellFacts(%q) = %q, %v; want %q, %v", tt.cmd, program, compound, tt.program, tt.compound)
		}
	}
}

func TestWithin(t *testing.T) {
	tests := []struct {
		p, dir string
		want   bool
	}{
		{"/home/ada/app/main.go", "/home/ada/app", true},
		{"/home/ada/app", "/home/ada/app", true},
		{"/home/ada/app2/main.go", "/home/ada/app", false},
		{"/home/ada/..app/x", "/home/ada", true},
		{"/home/ada", "/home/ada/app", false},
		{"/etc/passwd", "/home/ada/app", false},
		{"/x", "", false},
	}
	for _, tt := range tests {
		if got := within(tt.p, tt.dir); got != tt.want {
			t.Errorf("within(%q, %q) = %v, want %v", tt.p, tt.dir, got, tt.want)
		}
	}
}

func TestWarnings(t *testing.T) {
	e := newEnv(t)
	cfg, err := config.LoadLocal(e.config, e.lookup)
	if err != nil {
		t.Fatal(err)
	}
	if w := Warnings(cfg.Rules); len(w) != 0 {
		t.Errorf("the test policy has warnings: %q", w)
	}
	cfg.Rules[4].When = cfg.Rules[4].When[:1] // drop compound: false from safe-git
	if w := Warnings(cfg.Rules); len(w) != 1 || !strings.Contains(w[0], `rule "safe-git" allows shell commands without requiring compound: false`) {
		t.Errorf("warnings = %q", w)
	}
}

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/receipt"
	"github.com/matutozi/consequence-os/internal/store"
)

const testConfig = `
upstream: http://127.0.0.1:9090/mcp
upstream_receiver: payments-api
admin_token_env: TEST_CONSEQUENCED_ADMIN
receipts: { ed25519_key_env: TEST_CONSEQUENCED_ED, mldsa87_key_env: TEST_CONSEQUENCED_ML }
owners: [{ id: acme, approvers: [ada@acme.example] }]
agents:
  - { id: support-bot, owner_id: acme, api_key_env: TEST_CONSEQUENCED_KEY }
tools:
  payments.refund: irreversible
  notes.read: read
rules:
  - name: small-refunds
    tool: payments.refund
    when: { arg: amount, op: lte, value: 50 }
    action: allow
  - name: big-refunds
    tool: payments.refund
    action: ask
  - name: small-po-trusted-supplier
    tool: purchase_order.confirm
    when:
      - { arg: amount, op: lt, value: 500 }
      - { arg: supplier, op: in, value: [Coleman Cables, Acme Steel] }
    action: allow
`

func TestCheckWarnsWithoutUpstreamReceiver(t *testing.T) {
	writeTestConfig(t, "") // sets the env vars
	path := filepath.Join(t.TempDir(), "consequence.yaml")
	cfg := strings.Replace(testConfig, "upstream_receiver: payments-api\n", "", 1)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-config", path, "-check"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "upstream_receiver is not set, so receipts are v0") {
		t.Errorf("no warning about upstream_receiver:\n%s", out.String())
	}
}

func TestCheckPrintsWarnings(t *testing.T) {
	path := writeTestConfig(t, `
  - name: no-prod-deletes
    tool: db.delete_rows
    when: { arg: environment, op: eq, value: production }
    action: deny
  - name: no-prod-drops
    tool: db.drop_table
    when: { arg: environment, op: eq, value: production, fold: true }
    action: deny
`)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-config", path, "-check"}, &out); err != nil {
		t.Fatalf("a warning must not fail -check: %v", err)
	}
	for _, want := range []string{
		"warnings (1):",
		`rule "no-prod-deletes": deny matches environment only when it is written exactly`,
		"no-prod-drops: db.drop_table -> deny when environment eq production (any case)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, out.String())
		}
	}
}

func TestShippedConfigsHaveNoWarnings(t *testing.T) {
	writeTestConfig(t, "") // sets the signing keys; the shipped configs name their own env vars
	t.Setenv("CONSEQUENCE_ADMIN_TOKEN", "dev-admin")
	t.Setenv("CONSEQUENCE_KEY_SUPPORT_BOT", "dev-key")
	t.Setenv("CONSEQUENCE_KEY_RECEIVER_PAYMENTS", "dev-receiver")
	t.Setenv("CONSEQUENCE_SIGNING_KEY_ED25519", os.Getenv("TEST_CONSEQUENCED_ED"))
	t.Setenv("CONSEQUENCE_SIGNING_KEY_MLDSA87", os.Getenv("TEST_CONSEQUENCED_ML"))
	for _, path := range []string{"../../consequence.yaml", "../../examples/policies.yaml"} {
		var out bytes.Buffer
		if err := run(context.Background(), []string{"-config", path, "-check"}, &out); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if strings.Contains(out.String(), "warnings (") {
			t.Errorf("%s has policy warnings:\n%s", path, out.String())
		}
	}
}

func TestRun(t *testing.T) {
	// t.Setenv restores the variable when the test ends.
	path := writeTestConfig(t, "")

	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr string
	}{
		{"summary", []string{"-config", path, "-check"}, "config OK", ""},
		{"summary never prints the key", []string{"-config", path, "-check"}, "key from $TEST_CONSEQUENCED_KEY", ""},
		{"summary names the admin env var", []string{"-config", path, "-check"}, "admin token from:  $TEST_CONSEQUENCED_ADMIN", ""},
		{"summary lists approvers", []string{"-config", path, "-check"}, "acme, approvers: ada@acme.example", ""},
		{"summary shows storage", []string{"-config", path, "-check"}, "in memory", ""},
		{"genkeys", []string{"-genkeys"}, "CONSEQUENCE_SIGNING_KEY_MLDSA87=", ""},
		{"small refund", []string{"-config", path, "-tool", "payments.refund", "-args", `{"amount":20}`}, "action=allow rule=small-refunds", ""},
		{"big refund", []string{"-config", path, "-tool", "payments.refund", "-args", `{"amount":5000}`}, "action=ask rule=big-refunds", ""},
		{"read tool", []string{"-config", path, "-tool", "notes.read"}, "level=read action=allow rule=default score=0 reversibility=read source=config", ""},
		{"tool shows why", []string{"-config", path, "-tool", "rockets.launch"}, "score=80 reversibility=none source=config\n  because: rockets.launch isn't in the tools map, so it counts as irreversible.", ""},
		{"summary shows the default", []string{"-config", path, "-check"}, "when no rule matches: calls scoring under 20 are allowed, the rest ask", ""},
		{"summary joins conditions", []string{"-config", path, "-check"}, "when amount lt 500 and supplier in [Coleman Cables, Acme Steel]", ""},
		{"small po from trusted supplier", []string{"-config", path, "-tool", "purchase_order.confirm", "-args", `{"amount":120,"supplier":"Coleman Cables"}`}, "action=allow rule=small-po-trusted-supplier", ""},
		{"small po from unknown supplier", []string{"-config", path, "-tool", "purchase_order.confirm", "-args", `{"amount":120,"supplier":"Someone Else"}`}, "action=ask rule=default", ""},
		{"bad args", []string{"-config", path, "-tool", "notes.read", "-args", "[1]"}, "", "JSON object"},
		{"missing config", []string{"-config", "/does/not/exist.yaml"}, "", "read config"},
		{"-listen overrides the file", []string{"-config", path, "-listen", "0.0.0.0:9999", "-check"}, "listen:            0.0.0.0:9999\n  public URL:        http://localhost:9999", ""},
		{"-verify-audit needs a database", []string{"-config", path, "-verify-audit"}, "", "needs database_url_env or state_dir"},
		{"-listen is checked", []string{"-config", path, "-listen", "nonsense", "-check"}, "", `listen "nonsense" must look like`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(context.Background(), tt.args, &out)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if !strings.Contains(out.String(), tt.want) {
				t.Errorf("output %q does not contain %q", out.String(), tt.want)
			}
			if strings.Contains(out.String(), "dev-key") || strings.Contains(out.String(), "dev-admin") {
				t.Error("output leaks a secret")
			}
		})
	}
}

// writeTestConfig writes testConfig plus extra YAML to a temp file and sets
// the env vars it refers to. t.Setenv restores them when the test ends.
func writeTestConfig(t *testing.T, extra string) string {
	t.Helper()
	t.Setenv("TEST_CONSEQUENCED_KEY", "dev-key")
	t.Setenv("TEST_CONSEQUENCED_ADMIN", "dev-admin")
	ed, ml, err := receipt.GenerateSeeds()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_CONSEQUENCED_ED", ed)
	t.Setenv("TEST_CONSEQUENCED_ML", ml)
	path := filepath.Join(t.TempDir(), "consequence.yaml")
	if err := os.WriteFile(path, []byte(testConfig+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServeStopsOnCancel(t *testing.T) {
	path := writeTestConfig(t, "listen: 127.0.0.1:0\n") // port 0: the OS picks a free port
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-config", path}, &bytes.Buffer{}) }()

	time.Sleep(100 * time.Millisecond) // let the server start
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v, want nil after a clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestVersionFlag(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-version"}, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "consequenced dev\n" {
		t.Errorf("got %q", got)
	}
}

func TestListenFlagBeatsEnv(t *testing.T) {
	path := writeTestConfig(t, "")
	t.Setenv("CONSEQUENCE_LISTEN", "0.0.0.0:7000")
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-config", path, "-check"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "listen:            0.0.0.0:7000") {
		t.Errorf("env var ignored: %s", out.String())
	}
	out.Reset()
	if err := run(context.Background(), []string{"-config", path, "-listen", "127.0.0.1:7001", "-check"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "listen:            127.0.0.1:7001") {
		t.Errorf("flag didn't beat the env var: %s", out.String())
	}
}

func TestStateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	path := writeTestConfig(t, "state_dir: "+dir+"\n")
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-config", path, "-check"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "storage:           files in "+dir) {
		t.Errorf("summary doesn't name the state_dir:\n%s", out.String())
	}

	// A server has the directory open, and wrote two entries.
	st, err := store.OpenFile(dir, store.FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for i := 0; i < 2; i++ {
		if _, err := st.AppendAudit(context.Background(), audit.Entry{Time: time.Now(), AgentID: "a", OwnerID: "o", Tool: "x", Outcome: audit.OutcomeForwarded}); err != nil {
			t.Fatal(err)
		}
	}
	out.Reset()
	if err := run(context.Background(), []string{"-config", path, "-verify-audit"}, &out); err != nil {
		t.Fatalf("-verify-audit while the store is open: %v", err)
	}
	if !strings.Contains(out.String(), "audit chain intact: 2 entries checked") {
		t.Errorf("got %s", out.String())
	}
}

const hookPolicy = `
state_dir: STATE
tools: { Bash: irreversible }
rules:
  - name: no-force-push
    tool: Bash
    when: { arg: command, op: like, value: "git push --force*" }
    action: deny
  - name: anything-in-bash
    tool: Bash
    action: allow
`

func writeHookConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "claude-code.yaml")
	cfg := strings.ReplaceAll(hookPolicy, "STATE", filepath.Join(dir, "state"))
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHook(t *testing.T) {
	path := writeHookConfig(t)
	call := func(command string) string {
		return `{"hook_event_name":"PreToolUse","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"` + command + `"}}`
	}
	tests := []struct {
		name, stdin string
		args        []string
		wantCode    int // 0 means run returned nil
		wantOut     string
	}{
		{"deny", call("git push --force"), nil, 0, `"permissionDecision":"deny"`},
		{"allow says nothing", call("git status"), nil, 0, ""},
		{"bad input blocks", "nonsense", nil, 2, ""},
		{"unknown hook", call("ls"), []string{"-hook", "cursor"}, -1, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdin, stderr = strings.NewReader(tt.stdin), &bytes.Buffer{}
			t.Cleanup(func() { stdin, stderr = os.Stdin, os.Stderr })
			args := append([]string{"-config", path, "-hook", "claude-code"}, tt.args...)
			var out bytes.Buffer
			err := run(context.Background(), args, &out)
			var code exitCode
			switch {
			case tt.wantCode == -1:
				if err == nil || !strings.Contains(err.Error(), "the only hook is claude-code") {
					t.Errorf("err = %v", err)
				}
			case tt.wantCode == 0 && err != nil:
				t.Fatalf("err = %v", err)
			case tt.wantCode != 0 && (!errors.As(err, &code) || int(code) != tt.wantCode):
				t.Fatalf("err = %v, want exit %d", err, tt.wantCode)
			}
			if tt.wantOut == "" && out.Len() > 0 || !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("stdout = %q, want %q", out.String(), tt.wantOut)
			}
		})
	}
}

func TestHookCheck(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-config", writeHookConfig(t), "-hook", "claude-code", "-check"}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"config OK for the Claude Code hook",
		"agent:             local (owner local)",
		"2. anything-in-bash: Bash -> allow",
		"warnings (2):",
		`rule "no-force-push": deny matches command with a pattern`,
		`rule "anything-in-bash" allows shell commands without requiring compound: false`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestHookMode(t *testing.T) {
	for args, want := range map[string]bool{
		"-hook claude-code": true, "--hook claude-code": true, "-hook=claude-code": true, "--hook=x": true,
		"-hok claude-code -hook claude-code": true, "-check": false, "-hooks": false, "hook": false,
	} {
		if got := hookMode(strings.Fields(args)); got != want {
			t.Errorf("hookMode(%q) = %v, want %v", args, got, want)
		}
	}
}

func TestHookVerifyAudit(t *testing.T) {
	path := writeHookConfig(t)
	stdin, stderr = strings.NewReader(`{"hook_event_name":"PreToolUse","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"}}`), &bytes.Buffer{}
	t.Cleanup(func() { stdin, stderr = os.Stdin, os.Stderr })
	if err := run(context.Background(), []string{"-config", path, "-hook", "claude-code"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-config", path, "-hook", "claude-code", "-verify-audit"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "audit chain intact: 1 entries checked") {
		t.Errorf("got %s", out.String())
	}
	err := run(context.Background(), []string{"-config", path, "-hook", "claude-code", "-verify-audit", "-audit-head", "h.json"}, &out)
	if err == nil || !strings.Contains(err.Error(), "no signing keys") {
		t.Errorf("-audit-head with the hook: err = %v", err)
	}
}

func TestInitAndLog(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	path := filepath.Join(root, "dot-consequence", "claude-code.yaml")
	stdin, stderr = strings.NewReader(""), &bytes.Buffer{}
	t.Cleanup(func() { stdin, stderr = os.Stdin, os.Stderr })

	var out bytes.Buffer
	if err := run(context.Background(), []string{"-init", "claude-code", "-config", path, "-yes"}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Wrote the starter policy to " + path,
		"Added the hook to " + filepath.Join(project, ".claude", "settings.local.json"),
		"config OK for the Claude Code hook",
		"consequenced -hook claude-code -log -config " + path,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "warnings (") {
		t.Errorf("the starter has warnings:\n%s", out.String())
	}
	settings, err := os.ReadFile(filepath.Join(project, ".claude", "settings.local.json"))
	if err != nil || !strings.Contains(string(settings), "-hook claude-code -config "+path) {
		t.Fatalf("settings: %s %v", settings, err)
	}

	// Two calls through the hook, then the log.
	for _, cmd := range []string{"git status", "make deploy"} {
		stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","cwd":"` + project + `","tool_name":"Bash","tool_input":{"command":"` + cmd + `"}}`)
		if err := run(context.Background(), []string{"-hook", "claude-code", "-config", path}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	out.Reset()
	if err := run(context.Background(), []string{"-hook", "claude-code", "-config", path, "-log", "-n", "5"}, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[1], "forwarded") || !strings.Contains(lines[1], "commands-that-only-look") ||
		!strings.Contains(lines[2], "asked_user") || !strings.Contains(lines[2], "other-commands") {
		t.Errorf("log:\n%s", out.String())
	}

	// Saying no to a global install leaves the user's settings alone.
	t.Setenv("HOME", root)
	stdin = strings.NewReader("no\n")
	out.Reset()
	if err := run(context.Background(), []string{"-init", "claude-code", "-config", path, "-global"}, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Errorf("saying no wrote the global settings:\n%s", out.String())
	}
}

func TestLogNeedsAStore(t *testing.T) {
	err := run(context.Background(), []string{"-config", writeTestConfig(t, ""), "-log"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "needs database_url_env or state_dir") {
		t.Errorf("err = %v", err)
	}
}

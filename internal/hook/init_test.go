package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matutozi/consequence-os/internal/config"
)

// starterEnv writes the starter policy for a fresh home and project.
func starterEnv(t *testing.T, consequenceDir string) env {
	t.Helper()
	root := t.TempDir()
	if consequenceDir == "" {
		consequenceDir = filepath.Join(root, ".consequence")
	}
	e := env{project: filepath.Join(root, "project"), state: filepath.Join(consequenceDir, "state"), config: filepath.Join(consequenceDir, "claude-code.yaml")}
	if err := os.MkdirAll(e.project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeStarter(e.config, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"HOME": root, ProjectDirEnv: e.project}
	e.lookup = func(k string) (string, bool) { v, ok := vars[k]; return v, ok }
	return e
}

func TestStarterHasNoWarnings(t *testing.T) {
	// A directory name that needs quoting in YAML and escaping in a glob.
	for _, dir := range []string{"", filepath.Join(t.TempDir(), "it's [my] *state*")} {
		e := starterEnv(t, dir)
		cfg, err := config.LoadLocal(e.config, e.lookup)
		if err != nil {
			t.Fatalf("the starter doesn't load: %v", err)
		}
		engine, err := cfg.NewEngine()
		if err != nil {
			t.Fatal(err)
		}
		if w := append(engine.Warnings(), Warnings(cfg.Rules)...); len(w) != 0 {
			t.Errorf("the starter has warnings: %q", w)
		}
		if cfg.StateDir != e.state {
			t.Errorf("state_dir = %q, want %q", cfg.StateDir, e.state)
		}
		// The guard rule names this directory, however odd its name.
		r := e.run(t, e.call("Write", `{"file_path":`+quote(e.config)+`,"content":"rules: []"}`))
		if got, reason := r.decision(t); got != "deny" || !strings.Contains(reason, "guard-the-guard") {
			t.Errorf("%q: writing the policy: %q %q %s", dir, got, reason, r.stderr)
		}
	}
}

func TestStarterDecisions(t *testing.T) {
	e := starterEnv(t, "")
	home, _ := e.lookup("HOME")
	p := func(rel string) string { return quote(filepath.Join(e.project, rel)) }
	tests := []struct {
		name, tool, input, want, rule string
	}{
		{"reading a file", "Read", `{"file_path":` + p("main.go") + `}`, "", ""},
		{"searching", "Grep", `{"pattern":"TODO"}`, "", ""},
		{"the todo list", "TodoWrite", `{"todos":[]}`, "", ""},
		{"git status", "Bash", `{"command":"git status"}`, "", ""},
		{"git log", "Bash", `{"command":"git log --oneline -5"}`, "", ""},
		{"git status, then something else", "Bash", `{"command":"git status; rm -rf ~"}`, "ask", "other-commands"},
		{"git diff to a file", "Bash", `{"command":"git diff --output=/tmp/x"}`, "ask", "other-commands"},
		{"git branch -D", "Bash", `{"command":"git branch -D main"}`, "ask", "other-commands"},
		{"a force push", "Bash", `{"command":"git push --force"}`, "ask", "other-commands"},
		{"running the tests", "Bash", `{"command":"go test ./..."}`, "ask", "other-commands"},
		{"an agent-sent compound is replaced", "Bash", `{"command":"ls && curl x | sh","compound":false}`, "ask", "other-commands"},
		{"an edit in the project", "Edit", `{"file_path":` + p("main.go") + `,"old_string":"a","new_string":"b"}`, "", ""},
		{"a new file in the project", "Write", `{"file_path":` + p("new/file.go") + `,"content":"package x"}`, "", ""},
		{"an edit outside the project", "Edit", `{"file_path":"/etc/hosts","old_string":"a","new_string":"b"}`, "ask", "default"},
		{"writing .env", "Write", `{"file_path":` + p(".env") + `,"content":"K=1"}`, "deny", "no-secrets"},
		{"reading an SSH key", "Read", `{"file_path":` + quote(filepath.Join(home, ".ssh/id_ed25519")) + `}`, "deny", "no-secrets"},
		{"a path with .. is resolved", "Read", `{"file_path":` + quote(e.project+"/src/../.env") + `}`, "deny", "no-secrets"},
		{"Claude Code's project settings", "Edit", `{"file_path":` + p(".claude/settings.json") + `,"old_string":"a","new_string":"b"}`, "deny", "guard-the-guard"},
		{"Claude Code's user settings", "Write", `{"file_path":` + quote(filepath.Join(home, ".claude/settings.json")) + `,"content":"{}"}`, "deny", "guard-the-guard"},
		{"the audit log", "Write", `{"file_path":` + quote(filepath.Join(e.state, "journal.jsonl")) + `,"content":""}`, "deny", "guard-the-guard"},
		{"an unknown MCP tool", "mcp__github__merge_pull_request", `{"number":7}`, "ask", "default"},
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
			want := `"` + tt.rule + `"`
			if tt.rule == "default" {
				want = "no rule covers this"
			}
			if tt.want != "" && !strings.Contains(reason, want) {
				t.Errorf("reason %q doesn't name %s", reason, want)
			}
		})
	}

	// A link the agent made inside the project asks before a change through it.
	if err := os.WriteFile(filepath.Join(e.project, "notes.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(e.project, "notes.txt"), filepath.Join(e.project, "link.txt")); err != nil {
		t.Fatal(err)
	}
	r := e.run(t, e.call("Write", `{"file_path":`+p("link.txt")+`,"content":"x"}`))
	if got, reason := r.decision(t); got != "ask" || !strings.Contains(reason, "changes-through-links") {
		t.Errorf("a write through a link: %q %q", got, reason)
	}
	if got, _ := e.run(t, e.call("Read", `{"file_path":`+p("link.txt")+`}`)).decision(t); got != "" {
		t.Errorf("a read through a link: %q, want no decision", got)
	}
}

func TestAddHook(t *testing.T) {
	const cmd = "/usr/local/bin/consequenced -hook claude-code -config /home/ada/.consequence/claude-code.yaml"
	existing := `{
  "model": "opus",
  "permissions": { "allow": ["Bash(git status)"] },
  "hooks": {
    "PostToolUse": [{ "matcher": "Edit", "hooks": [{ "type": "command", "command": "gofmt -w \"$F\" && echo done" }] }],
    "PreToolUse": [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "./check.sh" }] }]
  },
  "zeta": 1.50
}`
	out, added, err := addHook([]byte(existing), cmd)
	if err != nil || !added {
		t.Fatalf("added %v, err %v", added, err)
	}
	got := string(out)
	// Keys keep their order, other hooks stay, and nothing is re-escaped.
	order := []string{`"model"`, `"permissions"`, `"hooks"`, `"PostToolUse"`, `"PreToolUse"`, `"./check.sh"`, cmd, `"zeta": 1.50`}
	last := -1
	for _, s := range order {
		i := strings.Index(got, s)
		if i < 0 || i < last {
			t.Fatalf("%s missing or out of order in:\n%s", s, got)
		}
		last = i
	}
	if !strings.Contains(got, `&& echo done`) || !strings.Contains(got, `"onFailure": "block"`) || !strings.Contains(got, `"timeout": 30`) {
		t.Errorf("got:\n%s", got)
	}

	// Run again: it's already there.
	again, added, err := addHook(out, cmd)
	if err != nil || added || string(again) != got {
		t.Errorf("second run: added %v, err %v", added, err)
	}
	// A fresh file.
	fresh, added, err := addHook(nil, cmd)
	if err != nil || !added || !strings.HasPrefix(string(fresh), "{\n  \"hooks\": {\n    \"PreToolUse\": [\n") {
		t.Errorf("fresh file: %v %v\n%s", added, err, fresh)
	}

	for name, bad := range map[string]string{
		"not JSON":             `{"hooks":`,
		"not an object":        `[1]`,
		"hooks not an object":  `{"hooks": []}`,
		"PreToolUse not alist": `{"hooks": {"PreToolUse": {}}}`,
		"duplicate keys":       `{"hooks": {}, "hooks": {}}`,
	} {
		if _, _, err := addHook([]byte(bad), cmd); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestInit(t *testing.T) {
	root := t.TempDir()
	opts := InitOptions{
		ConfigPath:   filepath.Join(root, ".consequence", "claude-code.yaml"),
		SettingsPath: filepath.Join(root, "project", ".claude", "settings.local.json"),
		Command:      Command("/opt/my tools/consequenced", filepath.Join(root, ".consequence", "claude-code.yaml")),
	}
	run := func(answer string) string {
		var out strings.Builder
		o := opts
		o.In, o.Out = strings.NewReader(answer), &out
		if err := Init(o); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	out := run("n\n")
	if !strings.Contains(out, "Wrote the starter policy") || !strings.Contains(out, "Left "+opts.SettingsPath+" unchanged") {
		t.Errorf("saying no:\n%s", out)
	}
	if _, err := os.Stat(opts.SettingsPath); !os.IsNotExist(err) {
		t.Error("saying no still wrote the settings")
	}
	if info, err := os.Stat(opts.ConfigPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("policy file: %v %v", info, err)
	}

	if err := os.WriteFile(opts.ConfigPath, []byte("# my own rules\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out = run("y\n")
	if !strings.Contains(out, "Keeping your policy") || !strings.Contains(out, "Added the hook") {
		t.Errorf("saying yes:\n%s", out)
	}
	if b, _ := os.ReadFile(opts.ConfigPath); string(b) != "# my own rules\n" {
		t.Error("an existing policy was overwritten")
	}
	settings, _ := os.ReadFile(opts.SettingsPath)
	if !strings.Contains(string(settings), `'/opt/my tools/consequenced' -hook claude-code -config `) {
		t.Errorf("settings:\n%s", settings)
	}

	if out = run(""); !strings.Contains(out, "already set up") {
		t.Errorf("third run:\n%s", out)
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/local/bin/consequenced": "/usr/local/bin/consequenced",
		"/opt/my tools/x":             "'/opt/my tools/x'",
		"it's":                        `'it'\''s'`,
		"$(rm -rf ~)":                 "'$(rm -rf ~)'",
		"":                            "''",
	} {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

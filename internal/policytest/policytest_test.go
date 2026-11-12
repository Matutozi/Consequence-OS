package policytest

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/matutozi/consequence-os/internal/config"
)

const testPolicy = `
tools: { payments.refund: irreversible, notes.read: read }
rules:
  - name: daily-cap
    tool: payments.refund
    limit: { sum: amount, max: 100, per: 24h }
    action: deny
  - name: small-refunds
    tool: payments.refund
    when: { arg: amount, op: lte, value: 50 }
    action: allow
  - name: office-hours-only
    tool: payments.refund
    outside: { days: [mon, tue, wed, thu, fri], hours: "09:00-17:00", timezone: UTC }
    action: ask
  - name: compound-shell
    tool: Bash
    when: { arg: compound, op: eq, value: true }
    action: ask
`

// write puts the policy and a test file in a directory, and returns the
// test file's path.
func write(t *testing.T, tests string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.test.yaml")
	if err := os.WriteFile(path, []byte("config: policy.yaml\n"+tests), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runFile(t *testing.T, path string) (Report, string) {
	t.Helper()
	f, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadPolicy(f.Config)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), cfg, f, time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	Print(&out, rep)
	return rep, out.String()
}

func TestPassingRun(t *testing.T) {
	rep, out := runFile(t, write(t, `
cases:
  - { name: small, tool: payments.refund, args: { amount: 20 }, want: allow, rule: small-refunds }
  - name: over the cap
    tool: payments.refund
    args: { amount: 20 }
    before: [{ args: { amount: 40 }, ago: 2h, times: 3 }] # 120 + 20, past 100
    want: deny
    rule: daily-cap
  - { name: text is not a number, tool: payments.refund, args: { amount: "20" }, want: ask, rule: default }
  - { name: after hours, tool: payments.refund, args: { amount: 70 }, at: "2026-11-16T20:00:00Z", want: ask, rule: office-hours-only }
  - { name: a read, tool: notes.read, want: allow }
  - name: exactly at the cap is still under it
    tool: payments.refund
    args: { amount: 20 }
    before: [{ args: { amount: 40 }, ago: 2h, times: 2 }] # 80 + 20 is 100, not past it
    want: allow
    rule: small-refunds
`))
	if rep.Failed() || !strings.Contains(out, "ok: 6 cases") || !strings.Contains(out, "note  no case reaches these rules: compound-shell") {
		t.Errorf("report:\n%s", out)
	}
}

func TestFailures(t *testing.T) {
	_, out := runFile(t, write(t, `
cases:
  - { name: wrong action, tool: payments.refund, args: { amount: 20 }, want: deny }
  - { name: wrong rule, tool: payments.refund, args: { amount: 20 }, want: allow, rule: daily-cap }
  - { name: no tool, want: allow }
  - { name: bad want, tool: notes.read, want: maybe }
  - { name: bad time, tool: notes.read, at: tomorrow, want: allow }
`))
	for _, want := range []string{
		"FAIL  wrong action: got allow by small-refunds, want deny",
		"FAIL  wrong rule: got allow by small-refunds, want allow by daily-cap",
		"FAIL  no tool: it names no tool",
		`FAIL  bad want: want "maybe" must be allow, ask or deny`,
		`FAIL  bad time: at "tomorrow" must be a time`,
		"FAIL: 5 of 5 cases",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
}

func TestEveryRuleRequired(t *testing.T) {
	rep, out := runFile(t, write(t, `
require_every_rule: true
cases:
  - { tool: payments.refund, args: { amount: 20 }, want: allow }
`))
	if !rep.Failed() || !strings.Contains(out, "FAIL  no case reaches these rules: daily-cap, office-hours-only, compound-shell") ||
		!strings.Contains(out, "every case passed, but not every rule is tested") {
		t.Errorf("report:\n%s", out)
	}
}

func TestHookCases(t *testing.T) {
	rep, out := runFile(t, write(t, `
hook: claude-code
project: /home/you/project
cases:
  - { name: a compound command, tool: Bash, args: { command: "ls; rm -rf ~" }, want: ask, rule: compound-shell }
  - { name: a plain one, tool: Bash, args: { command: ls }, want: ask, rule: default }
  - { name: compound sent by the agent is ignored, tool: Bash, args: { command: ls, compound: true }, want: ask, rule: default }
  - { name: set wins over the derivation, tool: Bash, args: { command: ls }, set: { compound: true }, want: ask, rule: compound-shell }
`))
	if rep.Failed() {
		t.Errorf("report:\n%s", out)
	}
}

func TestReadRefuses(t *testing.T) {
	for name, tt := range map[string]struct{ file, want string }{
		"a typo":       {"cases:\n  - { tool: x, wants: allow }\n", "field wants not found"},
		"no cases":     {"config: x.yaml\n", "has no cases"},
		"another hook": {"hook: cursor\ncases: [{ tool: x, want: allow }]\n", "the only hook is claude-code"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "t.yaml")
			_ = os.WriteFile(path, []byte(tt.file), 0o600)
			if _, err := Read(path); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

// Arguments get JSON's types: a number is a number, and a date YAML would
// read as a timestamp stays the text written, as a JSON caller sends it.
func TestArgumentTypes(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(`
rules:
  - { name: new-year, tool: report, when: { arg: day, op: eq, value: "2026-01-01" }, action: deny }
  - { name: twenty, tool: refund, when: [{ arg: amount, op: eq, value: 20 }, { arg: items.0.n, op: gte, value: 1.5 }], action: deny }
`), 0o600)
	path := filepath.Join(dir, "t.yaml")
	_ = os.WriteFile(path, []byte(`
config: p.yaml
cases:
  - { name: a date, tool: report, args: { day: 2026-01-01 }, want: deny, rule: new-year }
  - { name: numbers, tool: refund, args: { amount: 20, items: [{ n: 2 }] }, want: deny, rule: twenty }
  - { name: text, tool: refund, args: { amount: "20", items: [{ n: 2 }] }, want: ask }
`), 0o600)
	if rep, out := runFile(t, path); rep.Failed() {
		t.Errorf("report:\n%s", out)
	}
	_ = os.WriteFile(path, []byte("config: p.yaml\ncases:\n  - { tool: report, args: { day: 1, day: 2 }, want: deny }\n"), 0o600)
	if _, out := runFile(t, path); !strings.Contains(out, "day is given twice") {
		t.Errorf("a key given twice:\n%s", out)
	}
}

// The file's at is when its cases are made, unless a case says.
func TestFileTime(t *testing.T) {
	rep, out := runFile(t, write(t, `
at: 2026-11-16T20:00:00Z   # after hours; runFile's now is 10:00
cases:
  - { name: after hours by the file's time, tool: payments.refund, args: { amount: 70 }, want: ask, rule: office-hours-only }
  - { name: a case's own time wins, tool: payments.refund, args: { amount: 70 }, at: "2026-11-16T11:00:00Z", want: ask, rule: default }
`))
	if rep.Failed() {
		t.Errorf("report:\n%s", out)
	}
}

func TestJSONValue(t *testing.T) {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(`{ i: 20, f: 1.5, b: true, s: "x", d: 2026-01-01, z: null, l: [1, a] }`), &n); err != nil {
		t.Fatal(err)
	}
	v, err := jsonValue(&n)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"i": 20.0, "f": 1.5, "b": true, "s": "x", "d": "2026-01-01", "z": nil, "l": []any{1.0, "a"}}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("jsonValue = %#v\nwant %#v", v, want)
	}
}

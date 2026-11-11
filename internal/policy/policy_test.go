package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// exampleRules mirrors the example policy from the project brief.
func exampleRules() []Rule {
	return []Rule{
		{Name: "small-refunds", Tool: "payments.refund", When: Conditions{{Arg: "amount", Op: OpLte, Value: 50}}, Action: ActionAllow},
		{Name: "big-refunds", Tool: "payments.refund", Action: ActionAsk},
		{Name: "no-prod-deletes", Tool: "db.delete*", Action: ActionDeny},
	}
}

func exampleLevels() Levels {
	return Levels{
		"payments.refund": LevelIrreversible,
		"notes.read":      LevelRead,
		"notes.update":    LevelReversible,
	}
}

func TestEvaluate(t *testing.T) {
	engine, err := NewEngine(exampleRules(), exampleLevels())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	tests := []struct {
		name       string
		tool       string
		args       map[string]any
		wantAction Action
		wantRule   string
		wantLevel  Level
	}{
		{"small refund allowed", "payments.refund", map[string]any{"amount": 20.0}, ActionAllow, "small-refunds", LevelIrreversible},
		{"refund at the limit allowed", "payments.refund", map[string]any{"amount": 50.0}, ActionAllow, "small-refunds", LevelIrreversible},
		{"big refund asks", "payments.refund", map[string]any{"amount": 5000.0}, ActionAsk, "big-refunds", LevelIrreversible},
		{"refund without amount falls through to ask", "payments.refund", map[string]any{}, ActionAsk, "big-refunds", LevelIrreversible},
		{"refund with string amount falls through to ask", "payments.refund", map[string]any{"amount": "10"}, ActionAsk, "big-refunds", LevelIrreversible},
		{"refund with json.Number amount", "payments.refund", map[string]any{"amount": json.Number("12.5")}, ActionAllow, "small-refunds", LevelIrreversible},
		{"glob deny", "db.delete_users", nil, ActionDeny, "no-prod-deletes", LevelIrreversible},
		{"glob deny exact prefix", "db.delete", nil, ActionDeny, "no-prod-deletes", LevelIrreversible},
		{"default allow for read", "notes.read", nil, ActionAllow, DefaultRule, LevelRead},
		{"default ask for reversible", "notes.update", nil, ActionAsk, DefaultRule, LevelReversible},
		{"unknown tool is irreversible and asks", "rockets.launch", nil, ActionAsk, DefaultRule, LevelIrreversible},
	}

	for _, tt := range tests {
		// t.Run gives each case its own name in test output.
		t.Run(tt.name, func(t *testing.T) {
			got := evaluate(t, engine, tt.tool, tt.args)
			if got.Action != tt.wantAction || got.Rule != tt.wantRule || got.Level != tt.wantLevel {
				t.Errorf("Evaluate(%q) = %+v, want action=%s rule=%s level=%s",
					tt.tool, got, tt.wantAction, tt.wantRule, tt.wantLevel)
			}
		})
	}
}

func TestEvaluateFirstMatchWins(t *testing.T) {
	rules := []Rule{
		{Name: "deny-all-payments", Tool: "payments.*", Action: ActionDeny},
		{Name: "allow-refunds", Tool: "payments.refund", Action: ActionAllow},
	}
	engine, err := NewEngine(rules, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	got := evaluate(t, engine, "payments.refund", nil)
	if got.Rule != "deny-all-payments" || got.Action != ActionDeny {
		t.Errorf("got %+v, want the first rule to win", got)
	}
}

func TestConditionMatches(t *testing.T) {
	tests := []struct {
		name string
		cond Condition
		args map[string]any
		want bool
	}{
		{"eq number", Condition{Arg: "amount", Op: OpEq, Value: 50}, map[string]any{"amount": 50.0}, true},
		{"eq number mismatch", Condition{Arg: "amount", Op: OpEq, Value: 50}, map[string]any{"amount": 51.0}, false},
		{"eq string", Condition{Arg: "currency", Op: OpEq, Value: "USD"}, map[string]any{"currency": "USD"}, true},
		{"eq string is case sensitive", Condition{Arg: "currency", Op: OpEq, Value: "USD"}, map[string]any{"currency": "usd"}, false},
		{"eq bool", Condition{Arg: "dry_run", Op: OpEq, Value: true}, map[string]any{"dry_run": true}, true},
		{"eq string vs number", Condition{Arg: "amount", Op: OpEq, Value: "50"}, map[string]any{"amount": 50.0}, false},
		{"ne string", Condition{Arg: "env", Op: OpNe, Value: "prod"}, map[string]any{"env": "staging"}, true},
		{"ne same", Condition{Arg: "env", Op: OpNe, Value: "prod"}, map[string]any{"env": "prod"}, false},
		{"ne mismatched types never matches", Condition{Arg: "env", Op: OpNe, Value: "prod"}, map[string]any{"env": 1.0}, false},
		{"gt", Condition{Arg: "amount", Op: OpGt, Value: 50}, map[string]any{"amount": 50.01}, true},
		{"gt equal", Condition{Arg: "amount", Op: OpGt, Value: 50}, map[string]any{"amount": 50.0}, false},
		{"gte", Condition{Arg: "amount", Op: OpGte, Value: 50}, map[string]any{"amount": 50.0}, true},
		{"lt", Condition{Arg: "amount", Op: OpLt, Value: 50}, map[string]any{"amount": 49.0}, true},
		{"lte float value", Condition{Arg: "amount", Op: OpLte, Value: 49.5}, map[string]any{"amount": 49.5}, true},
		{"missing arg", Condition{Arg: "amount", Op: OpLt, Value: 50}, map[string]any{}, false},
		{"nil args", Condition{Arg: "amount", Op: OpLt, Value: 50}, nil, false},
		{"non-numeric arg for gt", Condition{Arg: "amount", Op: OpGt, Value: 1}, map[string]any{"amount": "lots"}, false},
		{"object arg", Condition{Arg: "amount", Op: OpEq, Value: 1}, map[string]any{"amount": map[string]any{"v": 1}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cond.matches(tt.args); got != tt.want {
				t.Errorf("matches = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchTool(t *testing.T) {
	tests := []struct {
		pattern, tool string
		want          bool
	}{
		{"payments.refund", "payments.refund", true},
		{"payments.refund", "payments.refunds", false},
		{"payments.*", "payments.refund", true},
		{"payments.*", "notes.read", false},
		{"db.delete*", "db.delete_all", true},
		{"*", "anything.at.all", true},
		{"notes.?ead", "notes.read", true},
		// * and ? match "/" too, so globs work on resource URIs.
		{"*", "resource:file:///etc/passwd", true},
		{"resource:*", "resource:file:///etc/ssl/certs/ca.pem", true},
		{"resource:file:///etc/*", "resource:file:///etc/ssl/certs/ca.pem", true},
		{"resource:file:///etc/*", "resource:file:///etcetera", false},
		{"resource:file:///etc/*", "prompt:file:///etc/x", false},
		{"resource:file:///a?b", "resource:file:///a/b", true},
		{"resource:file:///a[^/]b", "resource:file:///a/b", false}, // a class can still exclude "/"
		{"prompt:review-*", "prompt:review-pr", true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"~"+tt.tool, func(t *testing.T) {
			if got := matchTool(tt.pattern, tt.tool); got != tt.want {
				t.Errorf("matchTool(%q, %q) = %v, want %v", tt.pattern, tt.tool, got, tt.want)
			}
		})
	}
}

func TestNewEngineRejectsBadConfig(t *testing.T) {
	tests := []struct {
		name    string
		rules   []Rule
		levels  Levels
		wantErr string
	}{
		{"missing name", []Rule{{Tool: "x", Action: ActionAllow}}, nil, "name is required"},
		{"reserved name", []Rule{{Name: "default", Tool: "x", Action: ActionAllow}}, nil, "reserved"},
		{"missing tool", []Rule{{Name: "r", Action: ActionAllow}}, nil, "tool is required"},
		{"bad glob", []Rule{{Name: "r", Tool: "[", Action: ActionAllow}}, nil, "bad tool pattern"},
		{"bad action", []Rule{{Name: "r", Tool: "x", Action: "maybe"}}, nil, "unknown action"},
		{"duplicate name", []Rule{{Name: "r", Tool: "x", Action: ActionAllow}, {Name: "r", Tool: "y", Action: ActionDeny}}, nil, "duplicate"},
		{"bad op", []Rule{{Name: "r", Tool: "x", When: Conditions{{Arg: "a", Op: "between", Value: 1}}, Action: ActionAllow}}, nil, "unknown op"},
		{"missing arg", []Rule{{Name: "r", Tool: "x", When: Conditions{{Arg: "", Op: OpEq, Value: 1}}, Action: ActionAllow}}, nil, "arg is required"},
		{"lte with string", []Rule{{Name: "r", Tool: "x", When: Conditions{{Arg: "a", Op: OpLte, Value: "fifty"}}, Action: ActionAllow}}, nil, "numeric value"},
		{"eq with list", []Rule{{Name: "r", Tool: "x", When: Conditions{{Arg: "a", Op: OpEq, Value: []any{1}}}, Action: ActionAllow}}, nil, "must be a number"},
		{"bad level", nil, Levels{"x": "dangerous"}, "unknown level"},
		{"NUL in pattern", []Rule{{Name: "r", Tool: "a\x00b", Action: ActionAllow}}, nil, "bad tool pattern"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewEngine(tt.rules, tt.levels)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewEngine error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestReadsDefaultToReadLevel(t *testing.T) {
	levels := Levels{"resource:file:///secrets/key": LevelIrreversible, "notes.read": LevelRead}
	tests := []struct {
		name string
		want Level
	}{
		{"resource:file:///notes/welcome", LevelRead},
		{"prompt:summarize", LevelRead},
		{"resource:file:///secrets/key", LevelIrreversible}, // a listed level wins
		{"notes.read", LevelRead},
		{"rockets.launch", LevelIrreversible},
		{"resources.launch", LevelIrreversible}, // only the exact prefix counts
	}
	for _, tt := range tests {
		if got := levels.For(tt.name); got != tt.want {
			t.Errorf("For(%q) = %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestCatchAllRulesCoverReads(t *testing.T) {
	engine, err := NewEngine([]Rule{
		{Name: "public-notes", Tool: "resource:file:///notes/*", Action: ActionAllow},
		{Name: "nothing-else", Tool: "*", Action: ActionDeny},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for tool, want := range map[string]string{
		"resource:file:///notes/a/b.md": "public-notes",
		"resource:file:///etc/passwd":   "nothing-else",
		"prompt:summarize":              "nothing-else",
	} {
		if got := evaluate(t, engine, tool, nil); got.Rule != want {
			t.Errorf("%s: rule %q, want %q", tool, got.Rule, want)
		}
	}
}

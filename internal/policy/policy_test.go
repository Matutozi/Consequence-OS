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
			got := engine.Evaluate(tt.tool, tt.args)
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
	got := engine.Evaluate("payments.refund", nil)
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
		{"eq number", Condition{"amount", OpEq, 50}, map[string]any{"amount": 50.0}, true},
		{"eq number mismatch", Condition{"amount", OpEq, 50}, map[string]any{"amount": 51.0}, false},
		{"eq string", Condition{"currency", OpEq, "USD"}, map[string]any{"currency": "USD"}, true},
		{"eq string is case sensitive", Condition{"currency", OpEq, "USD"}, map[string]any{"currency": "usd"}, false},
		{"eq bool", Condition{"dry_run", OpEq, true}, map[string]any{"dry_run": true}, true},
		{"eq string vs number", Condition{"amount", OpEq, "50"}, map[string]any{"amount": 50.0}, false},
		{"ne string", Condition{"env", OpNe, "prod"}, map[string]any{"env": "staging"}, true},
		{"ne same", Condition{"env", OpNe, "prod"}, map[string]any{"env": "prod"}, false},
		{"ne mismatched types never matches", Condition{"env", OpNe, "prod"}, map[string]any{"env": 1.0}, false},
		{"gt", Condition{"amount", OpGt, 50}, map[string]any{"amount": 50.01}, true},
		{"gt equal", Condition{"amount", OpGt, 50}, map[string]any{"amount": 50.0}, false},
		{"gte", Condition{"amount", OpGte, 50}, map[string]any{"amount": 50.0}, true},
		{"lt", Condition{"amount", OpLt, 50}, map[string]any{"amount": 49.0}, true},
		{"lte float value", Condition{"amount", OpLte, 49.5}, map[string]any{"amount": 49.5}, true},
		{"missing arg", Condition{"amount", OpLt, 50}, map[string]any{}, false},
		{"nil args", Condition{"amount", OpLt, 50}, nil, false},
		{"non-numeric arg for gt", Condition{"amount", OpGt, 1}, map[string]any{"amount": "lots"}, false},
		{"object arg", Condition{"amount", OpEq, 1}, map[string]any{"amount": map[string]any{"v": 1}}, false},
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
		{"bad op", []Rule{{Name: "r", Tool: "x", When: Conditions{{"a", "between", 1}}, Action: ActionAllow}}, nil, "unknown op"},
		{"missing arg", []Rule{{Name: "r", Tool: "x", When: Conditions{{"", OpEq, 1}}, Action: ActionAllow}}, nil, "arg is required"},
		{"lte with string", []Rule{{Name: "r", Tool: "x", When: Conditions{{"a", OpLte, "fifty"}}, Action: ActionAllow}}, nil, "numeric value"},
		{"eq with list", []Rule{{Name: "r", Tool: "x", When: Conditions{{"a", OpEq, []any{1}}}, Action: ActionAllow}}, nil, "must be a number"},
		{"bad level", nil, Levels{"x": "dangerous"}, "unknown level"},
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

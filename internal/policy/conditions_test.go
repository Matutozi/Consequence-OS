package policy

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestEvaluateMultipleConditions(t *testing.T) {
	rules := []Rule{
		{
			Name: "small-trusted-po", Tool: "odoo.purchase_order.confirm",
			When: Conditions{
				{Arg: "amount", Op: OpLt, Value: 500},
				{Arg: "supplier", Op: OpIn, Value: []any{"Coleman Cables", "Acme Steel"}},
			},
			Action: ActionAllow,
		},
		{Name: "po-needs-manager", Tool: "odoo.purchase_order.confirm", Action: ActionAsk},
	}
	engine, err := NewEngine(rules, Levels{"odoo.purchase_order.confirm": LevelIrreversible})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	tests := []struct {
		name     string
		args     map[string]any
		wantRule string
	}{
		{"both hold", map[string]any{"amount": 120.0, "supplier": "Acme Steel"}, "small-trusted-po"},
		{"amount too high", map[string]any{"amount": 4800.0, "supplier": "Coleman Cables"}, "po-needs-manager"},
		{"supplier not on list", map[string]any{"amount": 120.0, "supplier": "Unknown Ltd"}, "po-needs-manager"},
		{"supplier missing", map[string]any{"amount": 120.0}, "po-needs-manager"},
		{"nothing given", nil, "po-needs-manager"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := engine.Evaluate("odoo.purchase_order.confirm", tt.args); got.Rule != tt.wantRule {
				t.Errorf("rule = %q, want %q", got.Rule, tt.wantRule)
			}
		})
	}
}

func TestListConditions(t *testing.T) {
	currencies := []any{"USD", "EUR"}
	codes := []any{1, 2, 3}

	tests := []struct {
		name string
		cond Condition
		args map[string]any
		want bool
	}{
		{"in string", Condition{"currency", OpIn, currencies}, map[string]any{"currency": "EUR"}, true},
		{"in string miss", Condition{"currency", OpIn, currencies}, map[string]any{"currency": "GBP"}, false},
		{"in number from JSON", Condition{"code", OpIn, codes}, map[string]any{"code": 2.0}, true},
		{"in wrong kind", Condition{"code", OpIn, codes}, map[string]any{"code": "2"}, false},
		{"in missing arg", Condition{"currency", OpIn, currencies}, map[string]any{}, false},
		{"not_in string", Condition{"currency", OpNotIn, currencies}, map[string]any{"currency": "GBP"}, true},
		{"not_in string hit", Condition{"currency", OpNotIn, currencies}, map[string]any{"currency": "USD"}, false},
		{"not_in wrong kind never matches", Condition{"currency", OpNotIn, currencies}, map[string]any{"currency": 5.0}, false},
		{"not_in missing arg never matches", Condition{"currency", OpNotIn, currencies}, map[string]any{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cond.matches(tt.args); got != tt.want {
				t.Errorf("matches = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestListConditionValidation(t *testing.T) {
	tests := []struct {
		name    string
		value   any
		wantErr string
	}{
		{"not a list", "USD", "non-empty list"},
		{"empty list", []any{}, "non-empty list"},
		{"nested list", []any{[]any{"USD"}}, "numbers, strings or bools"},
		{"mixed kinds", []any{"USD", 1}, "same kind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Condition{Arg: "a", Op: OpIn, Value: tt.value}.validate()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validate error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
	if err := (Condition{Arg: "a", Op: OpNotIn, Value: []any{1, 2.5}}).validate(); err != nil {
		t.Errorf("ints and floats are both numbers, got %v", err)
	}
}

func TestConditionsYAML(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		want    int // number of conditions decoded
		wantErr string
	}{
		{"single mapping", `when: { arg: amount, op: lte, value: 50 }`, 1, ""},
		{"list", "when:\n  - { arg: amount, op: lte, value: 50 }\n  - { arg: currency, op: in, value: [USD, EUR] }", 2, ""},
		{"absent", `name: r`, 0, ""},
		{"empty list", `when: []`, 0, "when list is empty"},
		{"scalar", `when: always`, 0, "condition or a list"},
		{"list of scalars", "when:\n  - amount", 0, "each when item"},
		{"typo in field", `when: { arg: amount, opp: lte, value: 50 }`, 0, `unknown condition field "opp"`},
		{"typo in list item", "when:\n  - { arg: amount, op: lte, valeu: 50 }", 0, `unknown condition field "valeu"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r struct {
				Name string     `yaml:"name"`
				When Conditions `yaml:"when"`
			}
			err := yaml.Unmarshal([]byte(tt.yaml), &r)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(r.When) != tt.want {
				t.Errorf("got %d conditions, want %d", len(r.When), tt.want)
			}
		})
	}
}

func TestValidationNamesTheFailingItem(t *testing.T) {
	rules := []Rule{{
		Name: "r", Tool: "x", Action: ActionAllow,
		When: Conditions{{"amount", OpLte, 50}, {"currency", OpIn, "USD"}},
	}}
	_, err := NewEngine(rules, nil)
	if err == nil || !strings.Contains(err.Error(), "when item 2") {
		t.Errorf("error = %v, want it to mention when item 2", err)
	}
}

func TestEngineCopiesRules(t *testing.T) {
	rules := []Rule{{Name: "r", Tool: "x", When: Conditions{{"amount", OpLte, 50}}, Action: ActionAllow}}
	engine, err := NewEngine(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules[0].When[0].Value = 1_000_000 // the caller changes its own copy afterwards
	if got := engine.Evaluate("x", map[string]any{"amount": 500.0}); got.Action == ActionAllow {
		t.Error("engine was affected by a later change to the caller's rules")
	}
}

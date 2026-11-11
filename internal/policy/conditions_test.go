package policy

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestEvaluateMultipleConditions(t *testing.T) {
	rules := []Rule{
		{
			Name: "small-trusted-po", Tool: "purchase_order.confirm",
			When: Conditions{
				{Arg: "amount", Op: OpLt, Value: 500},
				{Arg: "supplier", Op: OpIn, Value: []any{"Coleman Cables", "Acme Steel"}},
			},
			Action: ActionAllow,
		},
		{Name: "po-needs-manager", Tool: "purchase_order.confirm", Action: ActionAsk},
	}
	engine, err := NewEngine(rules, Levels{"purchase_order.confirm": LevelIrreversible})
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
			if got := evaluate(t, engine, "purchase_order.confirm", tt.args); got.Rule != tt.wantRule {
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
		{"in string", Condition{Arg: "currency", Op: OpIn, Value: currencies}, map[string]any{"currency": "EUR"}, true},
		{"in string miss", Condition{Arg: "currency", Op: OpIn, Value: currencies}, map[string]any{"currency": "GBP"}, false},
		{"in number from JSON", Condition{Arg: "code", Op: OpIn, Value: codes}, map[string]any{"code": 2.0}, true},
		{"in wrong kind", Condition{Arg: "code", Op: OpIn, Value: codes}, map[string]any{"code": "2"}, false},
		{"in missing arg", Condition{Arg: "currency", Op: OpIn, Value: currencies}, map[string]any{}, false},
		{"not_in string", Condition{Arg: "currency", Op: OpNotIn, Value: currencies}, map[string]any{"currency": "GBP"}, true},
		{"not_in string hit", Condition{Arg: "currency", Op: OpNotIn, Value: currencies}, map[string]any{"currency": "USD"}, false},
		{"not_in wrong kind never matches", Condition{Arg: "currency", Op: OpNotIn, Value: currencies}, map[string]any{"currency": 5.0}, false},
		{"not_in missing arg never matches", Condition{Arg: "currency", Op: OpNotIn, Value: currencies}, map[string]any{}, false},
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
		When: Conditions{{Arg: "amount", Op: OpLte, Value: 50}, {Arg: "currency", Op: OpIn, Value: "USD"}},
	}}
	_, err := NewEngine(rules, nil)
	if err == nil || !strings.Contains(err.Error(), "when item 2") {
		t.Errorf("error = %v, want it to mention when item 2", err)
	}
}

func TestEngineCopiesRules(t *testing.T) {
	rules := []Rule{{Name: "r", Tool: "x", When: Conditions{{Arg: "amount", Op: OpLte, Value: 50}}, Action: ActionAllow}}
	engine, err := NewEngine(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules[0].When[0].Value = 1_000_000 // the caller changes its own copy afterwards
	if got := evaluate(t, engine, "x", map[string]any{"amount": 500.0}); got.Action == ActionAllow {
		t.Error("engine was affected by a later change to the caller's rules")
	}
}

func TestFoldConditions(t *testing.T) {
	tests := []struct {
		name  string
		cond  Condition
		got   any
		match bool
	}{
		{"exact by default", Condition{Arg: "env", Op: OpEq, Value: "production"}, "Production", false},
		{"fold ignores case", Condition{Arg: "env", Op: OpEq, Value: "production", Fold: true}, "PRODUCTION", true},
		{"fold ignores outer spaces", Condition{Arg: "env", Op: OpEq, Value: "production", Fold: true}, " production\t", true},
		{"fold keeps inner differences", Condition{Arg: "env", Op: OpEq, Value: "production", Fold: true}, "prod", false},
		{"fold with ne", Condition{Arg: "env", Op: OpNe, Value: "staging", Fold: true}, "Staging", false},
		{"fold with in", Condition{Arg: "repo", Op: OpIn, Value: []any{"acme/api", "acme/billing"}, Fold: true}, "Acme/API", true},
		{"fold with not_in", Condition{Arg: "repo", Op: OpNotIn, Value: []any{"acme/api"}, Fold: true}, "ACME/api ", false},
		{"fold never makes a number match text", Condition{Arg: "env", Op: OpEq, Value: "1", Fold: true}, 1.0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cond.validate(); err != nil {
				t.Fatal(err)
			}
			if got := tt.cond.matches(map[string]any{tt.cond.Arg: tt.got}); got != tt.match {
				t.Errorf("matches(%q) = %v, want %v", tt.got, got, tt.match)
			}
		})
	}
}

func TestFoldValidation(t *testing.T) {
	tests := []struct {
		name string
		cond Condition
	}{
		{"on a number", Condition{Arg: "amount", Op: OpEq, Value: 50, Fold: true}},
		{"with a comparison", Condition{Arg: "env", Op: OpGt, Value: 5, Fold: true}},
		{"on a list of numbers", Condition{Arg: "n", Op: OpIn, Value: []any{1, 2}, Fold: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cond.validate(); err == nil || !strings.Contains(err.Error(), "fold") {
				t.Errorf("err = %v, want one about fold", err)
			}
		})
	}
}

func TestFoldInYAML(t *testing.T) {
	var r Rule
	src := "name: r\ntool: x\nwhen: { arg: env, op: eq, value: production, fold: true }\naction: deny\n"
	if err := yaml.Unmarshal([]byte(src), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.When) != 1 || !r.When[0].Fold {
		t.Errorf("fold not decoded: %+v", r.When)
	}
}

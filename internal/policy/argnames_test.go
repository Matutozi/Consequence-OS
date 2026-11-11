package policy

import (
	"context"
	"testing"
	"time"
)

// Many tool servers read argument names regardless of letter case, so a
// deny rule must not be dodged by "Environment" for "environment".
func TestArgumentNamesInAnotherCase(t *testing.T) {
	engine, err := NewEngine([]Rule{
		{Name: "no-prod-deletes", Tool: "db.delete_rows", When: Conditions{{Arg: "environment", Op: OpEq, Value: "production", Fold: true}}, Action: ActionDeny},
		{Name: "only-staging-skips-review", Tool: "db.drop_table", When: Conditions{{Arg: "environment", Op: OpNe, Value: "staging"}}, Action: ActionAsk},
		{Name: "small-refunds", Tool: "payments.refund", When: Conditions{{Arg: "amount", Op: OpLte, Value: 50}}, Action: ActionAllow},
		{Name: "everything-else-goes", Tool: "*", Action: ActionAllow},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		tool     string
		args     map[string]any
		wantRule string
	}{
		{"deny by the exact name", "db.delete_rows", map[string]any{"environment": "production"}, "no-prod-deletes"},
		{"deny by another case", "db.delete_rows", map[string]any{"Environment": "production"}, "no-prod-deletes"},
		{"deny by upper case", "db.delete_rows", map[string]any{"ENVIRONMENT": "Production"}, "no-prod-deletes"},
		{"ask with ne by another case", "db.drop_table", map[string]any{"Environment": "production"}, "only-staging-skips-review"},
		{"ne still holds back for the trusted value", "db.drop_table", map[string]any{"Environment": "staging"}, "everything-else-goes"},
		{"allow needs the exact name", "payments.refund", map[string]any{"Amount": 20.0}, "everything-else-goes"},
		{"allow by the exact name", "payments.refund", map[string]any{"amount": 20.0}, "small-refunds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evaluate(t, engine, tt.tool, tt.args); got.Rule != tt.wantRule {
				t.Errorf("rule = %q, want %q", got.Rule, tt.wantRule)
			}
		})
	}
}

func TestLimitsSumArgumentsInAnotherCase(t *testing.T) {
	engine, err := NewEngine([]Rule{
		{Name: "daily-cap", Tool: "payments.refund", Limit: &Limit{Sum: "amount", Max: 100, Per: 24 * time.Hour}, Action: ActionAsk},
		{Name: "refunds-go", Tool: "payments.refund", Action: ActionAllow},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	decide := func(args map[string]any) string {
		t.Helper()
		d, err := engine.Decide(ctx, Call{AgentID: "bot", Tool: "payments.refund", Args: args, At: monday10am}, NoUsage{})
		if err != nil {
			t.Fatal(err)
		}
		return d.Rule
	}
	if got := decide(map[string]any{"Amount": 5000.0}); got != "daily-cap" {
		t.Errorf("a big amount named Amount went to %q, want daily-cap", got)
	}
	if got := decide(map[string]any{"AMOUNT": -10.0}); got != "daily-cap" {
		t.Errorf("a negative amount named AMOUNT went to %q, want daily-cap", got)
	}
	if got := decide(map[string]any{"Amount": 20.0}); got != "refunds-go" {
		t.Errorf("a small amount went to %q, want refunds-go", got)
	}

	// The usage log counts it under the rule's name, so later calls see it.
	records := engine.UsageRecords(Call{AgentID: "bot", Tool: "payments.refund", Args: map[string]any{"Amount": 70.0}, At: monday10am})
	if len(records) != 1 || records[0].Values["amount"] != 70 {
		t.Errorf("usage records = %+v, want amount 70", records)
	}
}

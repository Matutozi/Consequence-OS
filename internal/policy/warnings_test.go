package policy

import (
	"strings"
	"testing"
)

func TestWarnings(t *testing.T) {
	prod := Condition{Arg: "environment", Op: OpEq, Value: "production"}
	repos := Condition{Arg: "repo", Op: OpIn, Value: []any{"acme/api", "acme/billing"}}
	tests := []struct {
		name  string
		rules []Rule
		want  []string // each must appear in its own warning, in order; none means no warnings
	}{
		{
			name:  "exact deny",
			rules: []Rule{{Name: "no-prod", Tool: "db.delete_rows", When: Conditions{prod}, Action: ActionDeny}},
			want:  []string{`rule "no-prod": deny matches environment only when it is written exactly`},
		},
		{
			name: "exception list followed by allow-everything",
			rules: []Rule{
				{Name: "critical", Tool: "github.merge_pull_request", When: Conditions{repos}, Action: ActionAsk},
				{Name: "other-merges", Tool: "github.*", Action: ActionAllow},
			},
			want: []string{`rule "critical": ask matches repo only when it is written exactly, so a variant falls through to rule "other-merges", which allows it`},
		},
		{
			name:  "fold silences it",
			rules: []Rule{{Name: "no-prod", Tool: "db.delete_rows", When: Conditions{{Arg: "environment", Op: OpEq, Value: "production", Fold: true}}, Action: ActionDeny}},
		},
		{
			name:  "an exact allow fails closed",
			rules: []Rule{{Name: "staging", Tool: "db.delete_rows", When: Conditions{{Arg: "environment", Op: OpEq, Value: "staging"}}, Action: ActionAllow}},
		},
		{
			name:  "numbers can't be written two ways",
			rules: []Rule{{Name: "big", Tool: "payments.refund", When: Conditions{{Arg: "amount", Op: OpGt, Value: 50}}, Action: ActionAsk}},
		},
		{
			name:  "ne fails closed",
			rules: []Rule{{Name: "not-staging", Tool: "db.delete_rows", When: Conditions{{Arg: "environment", Op: OpNe, Value: "staging"}}, Action: ActionDeny}},
		},
		{
			name: "a conditional allow afterwards isn't a catch-all",
			rules: []Rule{
				{Name: "no-prod", Tool: "db.delete_rows", When: Conditions{prod}, Action: ActionDeny},
				{Name: "small", Tool: "db.delete_rows", When: Conditions{{Arg: "max_rows", Op: OpLte, Value: 10}}, Action: ActionAllow},
			},
			want: []string{`rule "no-prod": deny matches environment only when it is written exactly, so a variant falls through to later rules`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := NewEngine(tt.rules, nil)
			if err != nil {
				t.Fatal(err)
			}
			got := e.Warnings()
			if len(got) != len(tt.want) {
				t.Fatalf("got %d warnings, want %d: %q", len(got), len(tt.want), got)
			}
			for i, w := range tt.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("warning %d = %q, want it to contain %q", i+1, got[i], w)
				}
			}
		})
	}
}

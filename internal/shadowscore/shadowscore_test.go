package shadowscore

import (
	"context"
	"strings"
	"testing"

	"github.com/matutozi/consequence-os/internal/config"
	"github.com/matutozi/consequence-os/internal/consequence"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/policytest"
)

func ids(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = "c"
	}
	return out
}

func TestAssess(t *testing.T) {
	spec := Spec{
		InternalDomains: []string{"acme.com"},
		Tools: map[string]Tool{
			"crm.delete": {Records: "ids"},
			"crm.export": {Records: "ids", Destination: "to"},
		},
	}
	base := func(score int) consequence.Assessment {
		return consequence.Assessment{Score: score, Reversibility: consequence.Reversible, Source: consequence.SourceConfig}
	}
	for _, tc := range []struct {
		name   string
		tool   string
		base   int
		args   map[string]any
		want   int
		reason string
	}{
		{"unlisted tool keeps its base", "other", 40, map[string]any{"ids": ids(500)}, 40, ""},
		{"one record", "crm.delete", 40, map[string]any{"ids": ids(1)}, 40, "1 record"},
		{"a few records", "crm.delete", 40, map[string]any{"ids": ids(5)}, 50, "5 records"},
		{"many records", "crm.delete", 40, map[string]any{"ids": ids(100)}, 60, "100 or more"},
		{"a count as a number", "crm.delete", 40, map[string]any{"ids": 3.0}, 50, "3 records"},
		{"no count counts as many", "crm.delete", 40, map[string]any{"all": true}, 60, "doesn't give a count"},
		{"a fractional count counts as many", "crm.delete", 40, map[string]any{"ids": 2.5}, 60, "doesn't give a count"},
		{"capped at 100", "crm.export", 80, map[string]any{"ids": ids(200), "to": "x@gmail.com"}, 100, "outside"},
		{"internal address", "crm.export", 40, map[string]any{"ids": ids(1), "to": "ops@acme.com"}, 40, "inside"},
		{"internal subdomain URL", "crm.export", 40, map[string]any{"ids": ids(1), "to": "https://files.eu.acme.com/x"}, 40, "inside"},
		{"look-alike domain is outside", "crm.export", 40, map[string]any{"ids": ids(1), "to": "ops@notacme.com"}, 60, "outside"},
		{"one outside recipient is enough", "crm.export", 40, map[string]any{"ids": ids(1), "to": []any{"a@acme.com", "b@gmail.com"}}, 60, "b@gmail.com"},
		{"no destination counts as outside", "crm.export", 40, map[string]any{"ids": ids(1)}, 60, "names no destination"},
		{"a read stays 0 whatever it does", "crm.export", 0, map[string]any{"ids": ids(500), "to": "x@gmail.com"}, 0, "outside"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := spec.Assess(base(tc.base), tc.tool, tc.args)
			if r.Score != tc.want {
				t.Errorf("score %d, want %d (factors %+v)", r.Score, tc.want, r.Factors)
			}
			var reasons []string
			for _, f := range r.Factors {
				reasons = append(reasons, f.Reason)
			}
			if got := strings.Join(reasons, "; "); !strings.Contains(got, tc.reason) {
				t.Errorf("reasons %q don't mention %q", got, tc.reason)
			}
			a := r.Assessment(base(tc.base))
			if err := a.Validate(); err != nil {
				t.Errorf("assessment: %v", err)
			}
			if len(a.Reasons) != len(r.Factors) {
				t.Errorf("assessment has %d reasons, want one per factor (%d)", len(a.Reasons), len(r.Factors))
			}
		})
	}
}

func TestWeightsOverride(t *testing.T) {
	spec := Spec{Tools: map[string]Tool{"crm.delete": {Records: "ids"}}, Weights: Weights{Many: 1.75, ManyAt: 10}}
	base := consequence.Assessment{Score: 40, Reversibility: consequence.Reversible, Source: consequence.SourceConfig}
	if got := spec.Assess(base, "crm.delete", map[string]any{"ids": ids(10)}).Score; got != 70 {
		t.Errorf("score %d, want 70", got)
	}
}

// The shipped example runs, and gives the results docs/shadow-score.md
// describes: with these weights, the context score changes no decision.
func TestExample(t *testing.T) {
	f, err := policytest.Read("../../examples/shadow-score/cases.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec := Spec{
		InternalDomains: []string{"acme.com"},
		Tools: map[string]Tool{
			"crm.delete_contacts": {Records: "contact_ids"},
			"crm.export_contacts": {Records: "contact_ids", Destination: "to"},
			"email.send":          {Records: "to", Destination: "to"},
		},
	}
	for _, tc := range []struct {
		config    string
		wantWrong int
	}{
		{"../../examples/shadow-score/consequence.yaml", 3},
		{"../../examples/shadow-score/consequence.arg-rules.yaml", 1},
	} {
		cfg, err := config.LoadPolicy(tc.config)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := Compare(context.Background(), cfg, f, spec)
		if err != nil {
			t.Fatal(err)
		}
		wrong := 0
		for _, r := range rows {
			if r.Today.Action != r.Context.Action {
				t.Errorf("%s, %s: today %s, context %s; the example expects no change", tc.config, r.Case.Name, r.Today.Action, r.Context.Action)
			}
			if r.Today.Action != r.Case.Want {
				wrong++
			}
		}
		if wrong != tc.wantWrong {
			t.Errorf("%s: %d cases decided against want:, expected %d", tc.config, wrong, tc.wantWrong)
		}
	}
}

func TestCompareRefusesLimits(t *testing.T) {
	cfg, err := config.LoadPolicy("../../examples/shadow-score/consequence.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f := &policytest.File{Cases: []policytest.Case{{Name: "x", Tool: "crm.get_contact", Want: policy.ActionAllow, Before: []policytest.Earlier{{}}}}}
	if _, err := Compare(context.Background(), cfg, f, Spec{}); err == nil || !strings.Contains(err.Error(), "before") {
		t.Errorf("err %v, want one about before:", err)
	}
}

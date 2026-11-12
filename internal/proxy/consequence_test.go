package proxy

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/consequence"
	"github.com/matutozi/consequence-os/internal/policy"
)

// resolverFunc lets a test answer assessments inline.
type resolverFunc func(tool string, args map[string]any) (consequence.Assessment, error)

func (f resolverFunc) Assess(_ context.Context, tool string, args map[string]any) (consequence.Assessment, error) {
	return f(tool, args)
}

// useResolver rebuilds the proxy with r assessing calls.
func (f *fixture) useResolver(t *testing.T, r consequence.Resolver) {
	t.Helper()
	opts := f.opts
	opts.Resolver = r
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	f.proxy = p
}

func TestCallIsNotForwardedWhenItCannotBeAssessed(t *testing.T) {
	tests := []struct {
		name     string
		resolver resolverFunc
	}{
		{"resolver fails", func(string, map[string]any) (consequence.Assessment, error) {
			return consequence.Assessment{}, errors.New("map unavailable")
		}},
		{"resolver returns nonsense", func(string, map[string]any) (consequence.Assessment, error) {
			return consequence.Assessment{Score: 250, Reversibility: consequence.Read, Source: consequence.SourceConfig}, nil
		}},
		{"resolver returns nothing", func(string, map[string]any) (consequence.Assessment, error) {
			return consequence.Assessment{}, nil
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.useResolver(t, tt.resolver)
			rec := f.do(http.MethodPost, call("notes.read", `{}`), nil)
			if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "consequence could not be assessed") {
				t.Errorf("got %d %s", rec.Code, rec.Body)
			}
			if f.up.count() != 0 {
				t.Error("an unassessed call was forwarded")
			}
		})
	}
}

func TestRulesSeeTheResolversAssessment(t *testing.T) {
	rules := append([]policy.Rule{{
		Name: "payment-data-asks", Tool: "*", Action: policy.ActionAsk,
		Consequence: policy.Conditions{{Arg: policy.FactDataClasses, Op: policy.OpIn, Value: []any{"payment"}}},
	}}, defaultRules()...)
	f := newFixtureWithRules(t, nil, rules)
	f.useResolver(t, resolverFunc(func(tool string, _ map[string]any) (consequence.Assessment, error) {
		a := consequence.Assessment{Score: 10, Reversibility: consequence.Read, Source: consequence.SourceMap, MapHash: "sha256:m",
			Reasons: []string{"notes.read reads the billing notes."}}
		if tool == "notes.read" {
			a.Score, a.DataClasses = 65, []string{"payment"}
		}
		return a, nil
	}))

	// A read tool the tools map would allow is held, because the map says
	// it touches payment data.
	body := f.do(http.MethodPost, call("notes.read", `{"note_id":"billing"}`), nil).Body.String()
	if !strings.Contains(body, "Approval pending") || !strings.Contains(body, "payment-data-asks") {
		t.Fatalf("notes.read: %s", body)
	}
	entries, _ := f.store.ListAudit(context.Background(), audit.Filter{Limit: 1})
	if e := entries[0]; e.Score != 65 || e.Level != policy.LevelRead || e.Outcome != audit.OutcomeHeld {
		t.Errorf("audit entry = %+v, want score 65, level read, held", e)
	}
	a, _, err := f.approvals.View(context.Background(), entries[0].ApprovalID, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Score != 65 || len(a.Reasons) != 1 || a.Reasons[0] != "notes.read reads the billing notes." {
		t.Errorf("approval carries score %d and reasons %q", a.Score, a.Reasons)
	}

	// Another tool scored 10 by the map falls to the default and is allowed.
	if body := f.do(http.MethodPost, call("weather.today", `{}`), nil).Body.String(); !strings.Contains(body, "from upstream") {
		t.Errorf("weather.today: %s", body)
	}
}

func TestDenyRuleCatchesArgumentNamesInAnotherCase(t *testing.T) {
	rules := []policy.Rule{
		{Name: "no-prod-deletes", Tool: "db.delete_rows", When: policy.Conditions{{Arg: "environment", Op: policy.OpEq, Value: "production", Fold: true}}, Action: policy.ActionDeny},
		{Name: "deletes-otherwise-go", Tool: "db.delete_rows", Action: policy.ActionAllow},
	}
	f := newFixtureWithRules(t, nil, rules)
	body := f.do(http.MethodPost, call("db.delete_rows", `{"Environment":"production","table":"users"}`), nil).Body.String()
	if !strings.Contains(body, "no-prod-deletes") || f.up.count() != 0 {
		t.Errorf("a delete with Environment=production got through: %s", body)
	}
}

func TestDenyRuleCatchesNestedArguments(t *testing.T) {
	rules := []policy.Rule{
		{Name: "no-prod-deletes", Tool: "db.delete_rows", When: policy.Conditions{{Arg: "options.environment", Op: policy.OpEq, Value: "production", Fold: true}}, Action: policy.ActionDeny},
		{Name: "deletes-otherwise-go", Tool: "db.delete_rows", Action: policy.ActionAllow},
	}
	f := newFixtureWithRules(t, nil, rules)
	for _, args := range []string{
		`{"table":"users","options":{"environment":"production"}}`,
		`{"table":"users","options":{"Environment":"Production"}}`,
	} {
		body := f.do(http.MethodPost, call("db.delete_rows", args), nil).Body.String()
		if !strings.Contains(body, "no-prod-deletes") {
			t.Errorf("%s got through: %s", args, body)
		}
	}
	// Two nested names differing only in case are refused before the policy runs.
	rec := f.do(http.MethodPost, call("db.delete_rows", `{"options":{"environment":"staging","Environment":"production"}}`), nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "differ only in letter case") {
		t.Errorf("nested case variants: %d %s", rec.Code, rec.Body)
	}
	if f.up.count() != 0 {
		t.Errorf("%d calls reached the upstream", f.up.count())
	}
}

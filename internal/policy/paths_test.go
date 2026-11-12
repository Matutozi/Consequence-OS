package policy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func jsonArgs(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestNestedConditions(t *testing.T) {
	prod := func(arg string) Condition { return Condition{Arg: arg, Op: OpEq, Value: "production"} }
	small := Condition{Arg: "items.*.amount", Op: OpLte, Value: 50}
	tests := []struct {
		name        string
		cond        Condition
		args        string
		deny, allow bool // how a deny rule and an allow rule judge it
	}{
		{"an object field", prod("options.environment"), `{"options":{"environment":"production"}}`, true, true},
		{"a different value", prod("options.environment"), `{"options":{"environment":"staging"}}`, false, false},
		{"another case of a nested name", prod("options.environment"), `{"options":{"Environment":"production"}}`, true, false},
		{"another case of the outer name", prod("options.environment"), `{"Options":{"environment":"production"}}`, true, false},
		{"missing", prod("options.environment"), `{"options":{}}`, false, false},
		{"not an object", prod("options.environment"), `{"options":"production"}`, false, false},
		{"deeper", prod("a.b.c"), `{"a":{"b":{"c":"production"}}}`, true, true},

		{"every item small", small, `{"items":[{"amount":10},{"amount":50}]}`, true, true},
		{"one item too big", small, `{"items":[{"amount":10},{"amount":5000}]}`, true, false}, // deny sees the small one; allow sees the big one
		{"one item without the field", small, `{"items":[{"amount":10},{"sku":"x"}]}`, true, false},
		{"one item the wrong type", small, `{"items":[{"amount":10},{"amount":"5000"}]}`, true, false},
		{"an empty list", small, `{"items":[]}`, false, false},
		{"not a list", small, `{"items":{"amount":10}}`, false, false},
		{"members of an object", small, `{"items":{"a":{"amount":10},"b":{"amount":20}}}`, true, true},
		{"one item by index", Condition{Arg: "items.1.amount", Op: OpGt, Value: 100}, `{"items":[{"amount":10},{"amount":500}]}`, true, true},
		{"an index past the end", Condition{Arg: "items.5.amount", Op: OpGt, Value: 100}, `{"items":[{"amount":500}]}`, false, false},
		{"a list of text", Condition{Arg: "tags.*", Op: OpIn, Value: []any{"prod"}}, `{"tags":["dev","prod"]}`, true, false},

		{"a name with a dot wins over the path", prod("db.env"), `{"db.env":"production","db":{"env":"staging"}}`, true, true},
		{"the path when there's no such name", prod("db.env"), `{"db":{"env":"production"}}`, true, true},
		{"top level is as it was", prod("environment"), `{"environment":"production"}`, true, true},
		{"top level, another case", prod("environment"), `{"Environment":"production"}`, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cond.validate(); err != nil {
				t.Fatal(err)
			}
			args := jsonArgs(t, tt.args)
			if got := tt.cond.holds(args, true); got != tt.deny {
				t.Errorf("as a deny rule: %v, want %v", got, tt.deny)
			}
			if got := tt.cond.holds(args, false); got != tt.allow {
				t.Errorf("as an allow rule: %v, want %v", got, tt.allow)
			}
		})
	}
}

// The case the roadmap names: a deny rule on a nested argument, followed
// by an allow-everything rule.
func TestNestedDenyBeforeAllowEverything(t *testing.T) {
	e, err := NewEngine([]Rule{
		{Name: "no-prod-deletes", Tool: "db.delete_rows", When: Conditions{{Arg: "options.environment", Op: OpEq, Value: "production", Fold: true}}, Action: ActionDeny},
		{Name: "small-orders", Tool: "orders.create", When: Conditions{{Arg: "items.*.amount", Op: OpLte, Value: 100}}, Action: ActionAllow},
		{Name: "everything-else", Tool: "*", Action: ActionAllow},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		tool, args string
		want       Action
		rule       string
	}{
		{"db.delete_rows", `{"table":"users","options":{"environment":"Production"}}`, ActionDeny, "no-prod-deletes"},
		{"db.delete_rows", `{"table":"users","options":{"ENVIRONMENT":"production"}}`, ActionDeny, "no-prod-deletes"},
		{"db.delete_rows", `{"table":"users","options":{"environment":"staging"}}`, ActionAllow, "everything-else"},
		{"orders.create", `{"items":[{"amount":20},{"amount":30}]}`, ActionAllow, "small-orders"},
		{"orders.create", `{"items":[{"amount":20},{"amount":9000}]}`, ActionAllow, "everything-else"}, // not small-orders: one item is too big
	}
	for _, tt := range tests {
		d, err := e.Decide(context.Background(), Call{AgentID: "a", Tool: tt.tool, Args: jsonArgs(t, tt.args)}, NoUsage{})
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != tt.want || d.Rule != tt.rule {
			t.Errorf("%s %s: %s by %s, want %s by %s", tt.tool, tt.args, d.Action, d.Rule, tt.want, tt.rule)
		}
	}
}

func TestNestedLimits(t *testing.T) {
	e, err := NewEngine([]Rule{
		{Name: "daily-orders", Tool: "orders.create", Limit: &Limit{Sum: "items.*.amount", Max: 100, Per: 24 * time.Hour}, Action: ActionDeny},
		{Name: "orders", Tool: "orders.create", Action: ActionAllow},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	usage := &countingUsage{}
	at := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	call := func(args string) Call {
		return Call{AgentID: "a", Tool: "orders.create", Args: jsonArgs(t, args), At: at}
	}
	steps := []struct {
		args string
		want Action
	}{
		{`{"items":[{"amount":30},{"amount":40}]}`, ActionAllow},  // 70: every item counts
		{`{"items":[{"amount":20},{"amount":20}]}`, ActionDeny},   // 70 + 40 is over 100
		{`{"items":[{"amount":10},{"amount":-500}]}`, ActionDeny}, // a negative item can't make room
		{`{"items":[{"amount":30}]}`, ActionAllow},                // 100 exactly
	}
	for i, s := range steps {
		c := call(s.args)
		d, err := e.Decide(context.Background(), c, usage)
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != s.want {
			t.Fatalf("step %d %s: %s by %s, want %s", i+1, s.args, d.Action, d.Rule, s.want)
		}
		if d.Action == ActionAllow {
			usage.records = append(usage.records, e.UsageRecords(c)...)
		}
	}
	if got := usage.records[0].Values["items.*.amount"]; got != 70 {
		t.Errorf("the first call was recorded as %v, want 70", got)
	}
}

// countingUsage is a UsageCounter over records kept in memory.
type countingUsage struct{ records []UsageRecord }

func (u *countingUsage) CountUsage(_ context.Context, agent, scope string, since time.Time, sumArg string) (int, float64, error) {
	n, sum := 0, 0.0
	for _, r := range u.records {
		if r.AgentID == agent && r.Tool == scope && r.At.After(since.Add(-time.Nanosecond)) {
			n++
			sum += r.Values[sumArg]
		}
	}
	return n, sum, nil
}

func TestPathValidation(t *testing.T) {
	for arg, want := range map[string]string{
		"options..environment": "empty part",
		".environment":         "empty part",
		"options.":             "empty part",
		"*.amount":             "must start with an argument's name",
	} {
		err := Condition{Arg: arg, Op: OpEq, Value: "x"}.validate()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", arg, err, want)
		}
	}
	if err := (&Limit{Sum: "items..amount", Max: 1, Per: time.Hour}).validate(); err == nil {
		t.Error("a bad limit.sum path was accepted")
	}
	for _, ok := range []string{"options.environment", "items.*.amount", "items.0.amount", "tags.*", "plain"} {
		if err := (Condition{Arg: ok, Op: OpEq, Value: "x"}).validate(); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}

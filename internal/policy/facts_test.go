package policy

import (
	"context"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/matutozi/consequence-os/internal/consequence"
)

// assessed is a full assessment from a map, for testing every fact.
func assessed() consequence.Assessment {
	return consequence.Assessment{
		Score: 82, Reversibility: consequence.None, BlastRadius: 12, Source: consequence.SourceMap, MapHash: "sha256:abc",
		DataClasses: []string{"payment", "personal"}, Owners: []string{"@billing"}, Targets: []string{"path:internal/billing/"},
	}
}

func TestFactConditions(t *testing.T) {
	bare := consequence.Assessment{Score: 0, Reversibility: consequence.Read, Source: consequence.SourceConfig}
	tests := []struct {
		name string
		cond Condition
		a    consequence.Assessment
		want bool
	}{
		{"score gte", Condition{Arg: FactScore, Op: OpGte, Value: 70}, assessed(), true},
		{"score gte miss", Condition{Arg: FactScore, Op: OpGte, Value: 90}, assessed(), false},
		{"score lt", Condition{Arg: FactScore, Op: OpLt, Value: 90}, assessed(), true},
		{"score eq", Condition{Arg: FactScore, Op: OpEq, Value: 82}, assessed(), true},
		{"score ne", Condition{Arg: FactScore, Op: OpNe, Value: 82}, assessed(), false},
		{"score in", Condition{Arg: FactScore, Op: OpIn, Value: []any{80, 82}}, assessed(), true},
		{"score not_in", Condition{Arg: FactScore, Op: OpNotIn, Value: []any{80, 82}}, assessed(), false},
		{"score 0 is a value, not missing", Condition{Arg: FactScore, Op: OpLte, Value: 0}, bare, true},
		{"blast radius gt", Condition{Arg: FactBlastRadius, Op: OpGt, Value: 10}, assessed(), true},
		{"unknown blast radius never matches", Condition{Arg: FactBlastRadius, Op: OpLt, Value: 10}, bare, false},
		{"reversibility eq", Condition{Arg: FactReversibility, Op: OpEq, Value: "none"}, assessed(), true},
		{"reversibility ne", Condition{Arg: FactReversibility, Op: OpNe, Value: "read"}, assessed(), true},
		{"reversibility in", Condition{Arg: FactReversibility, Op: OpIn, Value: []any{"compensable", "none"}}, assessed(), true},
		{"reversibility not_in", Condition{Arg: FactReversibility, Op: OpNotIn, Value: []any{"read"}}, bare, false},
		{"source eq", Condition{Arg: FactSource, Op: OpEq, Value: "map"}, assessed(), true},
		{"source eq config", Condition{Arg: FactSource, Op: OpEq, Value: "config"}, assessed(), false},
		{"list eq matches any item", Condition{Arg: FactDataClasses, Op: OpEq, Value: "personal"}, assessed(), true},
		{"list in matches any item", Condition{Arg: FactDataClasses, Op: OpIn, Value: []any{"auth", "payment"}}, assessed(), true},
		{"list in miss", Condition{Arg: FactDataClasses, Op: OpIn, Value: []any{"auth"}}, assessed(), false},
		{"list ne needs no item equal", Condition{Arg: FactDataClasses, Op: OpNe, Value: "payment"}, assessed(), false},
		{"list ne holds", Condition{Arg: FactDataClasses, Op: OpNe, Value: "auth"}, assessed(), true},
		{"list not_in needs no item in", Condition{Arg: FactDataClasses, Op: OpNotIn, Value: []any{"personal"}}, assessed(), false},
		{"list not_in holds", Condition{Arg: FactDataClasses, Op: OpNotIn, Value: []any{"auth"}}, assessed(), true},
		{"list fold", Condition{Arg: FactOwners, Op: OpEq, Value: "@BILLING", Fold: true}, assessed(), true},
		{"targets in", Condition{Arg: FactTargets, Op: OpIn, Value: []any{"path:internal/billing/"}}, assessed(), true},
		{"empty list never matches in", Condition{Arg: FactDataClasses, Op: OpIn, Value: []any{"payment"}}, bare, false},
		{"empty list never matches not_in", Condition{Arg: FactDataClasses, Op: OpNotIn, Value: []any{"payment"}}, bare, false},
		{"empty owners never match ne", Condition{Arg: FactOwners, Op: OpNe, Value: "@billing"}, bare, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateFact(tt.cond); err != nil {
				t.Fatalf("invalid condition: %v", err)
			}
			if got := tt.cond.matchFact(tt.a); got != tt.want {
				t.Errorf("matchFact = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFactValidation(t *testing.T) {
	tests := []struct {
		name string
		cond Condition
		want string
	}{
		{"unknown fact", Condition{Arg: "amount", Op: OpGt, Value: 5}, "unknown fact"},
		{"score as text", Condition{Arg: FactScore, Op: OpEq, Value: "high"}, "is a number"},
		{"score list of text", Condition{Arg: FactScore, Op: OpIn, Value: []any{"high"}}, "is a number"},
		{"reversibility compared", Condition{Arg: FactReversibility, Op: OpGt, Value: 1}, "is text"},
		{"reversibility typo", Condition{Arg: FactReversibility, Op: OpEq, Value: "irreversible"}, `"irreversible" is none`},
		{"reversibility typo in list", Condition{Arg: FactReversibility, Op: OpIn, Value: []any{"read", "nonee"}}, "unknown reversibility"},
		{"unknown source", Condition{Arg: FactSource, Op: OpEq, Value: "guess"}, "unknown source"},
		{"list compared with gt", Condition{Arg: FactDataClasses, Op: OpGt, Value: 1}, "is text"},
		{"list with numbers", Condition{Arg: FactOwners, Op: OpIn, Value: []any{1}}, "is text"},
		{"bad op still caught", Condition{Arg: FactScore, Op: "between", Value: 1}, "unknown op"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateFact(tt.cond); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestRulesMatchOnConsequence(t *testing.T) {
	engine, err := NewEngine([]Rule{
		{Name: "payment-data-is-off-limits", Tool: "*", Consequence: Conditions{{Arg: FactDataClasses, Op: OpIn, Value: []any{"payment"}}}, Action: ActionDeny},
		{Name: "high-consequence-asks", Tool: "*", Consequence: Conditions{{Arg: FactScore, Op: OpGte, Value: 70}}, Action: ActionAsk},
		{Name: "cheap-reversible-goes", Tool: "notes.*", Consequence: Conditions{
			{Arg: FactReversibility, Op: OpEq, Value: "reversible"}, {Arg: FactScore, Op: OpLt, Value: 50},
		}, Action: ActionAllow},
	}, Levels{"notes.update": LevelReversible, "notes.read": LevelRead})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tests := []struct {
		name     string
		call     Call
		wantRule string
		want     Action
	}{
		{"map says payment data", Call{Tool: "db.query", Consequence: assessed()}, "payment-data-is-off-limits", ActionDeny},
		{"config scores an unlisted tool 80", Call{Tool: "rockets.launch"}, "high-consequence-asks", ActionAsk},
		{"reversible note update", Call{Tool: "notes.update"}, "cheap-reversible-goes", ActionAllow},
		{"read falls to the default", Call{Tool: "notes.read"}, DefaultRule, ActionAllow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := engine.Decide(ctx, tt.call, nil)
			if err != nil {
				t.Fatal(err)
			}
			if d.Rule != tt.wantRule || d.Action != tt.want {
				t.Errorf("got %s by %q, want %s by %q", d.Action, d.Rule, tt.want, tt.wantRule)
			}
		})
	}
}

func TestDefaultComesFromTheScore(t *testing.T) {
	ctx := context.Background()
	at := func(score int) Call {
		return Call{Tool: "x", Consequence: consequence.Assessment{Score: score, Reversibility: consequence.Reversible, Source: consequence.SourceConfig}}
	}
	tests := []struct {
		allowBelow int
		score      int
		want       Action
	}{
		{DefaultAllowBelow, 0, ActionAllow},
		{DefaultAllowBelow, 19, ActionAllow},
		{DefaultAllowBelow, 20, ActionAsk},
		{DefaultAllowBelow, 80, ActionAsk},
		{0, 0, ActionAsk}, // 0 allows nothing by default
		{50, 40, ActionAllow},
	}
	for _, tt := range tests {
		engine, err := NewEngine(nil, nil, AllowBelow(tt.allowBelow))
		if err != nil {
			t.Fatal(err)
		}
		d, err := engine.Decide(ctx, at(tt.score), nil)
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != tt.want || d.Rule != DefaultRule {
			t.Errorf("allow below %d, score %d: got %s, want %s", tt.allowBelow, tt.score, d.Action, tt.want)
		}
	}
	for _, bad := range []int{-1, 101} {
		if _, err := NewEngine(nil, nil, AllowBelow(bad)); err == nil || !strings.Contains(err.Error(), "default_allow_below") {
			t.Errorf("AllowBelow(%d): err = %v", bad, err)
		}
	}
}

func TestUnsetAssessmentIsNeverHarmless(t *testing.T) {
	engine, err := NewEngine(nil, Levels{"payments.refund": LevelIrreversible})
	if err != nil {
		t.Fatal(err)
	}
	d, err := engine.Decide(context.Background(), Call{Tool: "payments.refund"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionAsk || d.Consequence.Score != 80 || d.Level != LevelIrreversible || d.Consequence.Source != consequence.SourceConfig {
		t.Errorf("decision without an assessment = %+v, want the tools map's 80, irreversible, ask", d)
	}
}

func TestInvalidAssessmentIsAnError(t *testing.T) {
	engine, _ := NewEngine(nil, nil)
	bad := consequence.Assessment{Score: 500, Reversibility: consequence.Read, Source: consequence.SourceMap, MapHash: "sha256:x"}
	if _, err := engine.Decide(context.Background(), Call{Tool: "x", Consequence: bad}, nil); err == nil {
		t.Error("an out-of-range score was decided on")
	}
}

func TestLevelComesFromTheAssessment(t *testing.T) {
	engine, _ := NewEngine(nil, Levels{"x": LevelRead})
	for rev, want := range map[consequence.Reversibility]Level{
		consequence.Read: LevelRead, consequence.Reversible: LevelReversible,
		consequence.Compensable: LevelIrreversible, consequence.None: LevelIrreversible,
	} {
		a := consequence.Assessment{Score: 50, Reversibility: rev, Source: consequence.SourceConfig}
		if d, _ := engine.Decide(context.Background(), Call{Tool: "x", Consequence: a}, nil); d.Level != want {
			t.Errorf("%s: level %s, want %s", rev, d.Level, want)
		}
	}
}

func TestConsequenceInYAML(t *testing.T) {
	var r Rule
	src := "name: r\ntool: \"*\"\nconsequence:\n  - { arg: score, op: gte, value: 70 }\n  - { arg: data_classes, op: in, value: [payment] }\naction: ask\n"
	if err := yaml.Unmarshal([]byte(src), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Consequence) != 2 || r.Consequence[1].Arg != FactDataClasses {
		t.Fatalf("consequence not decoded: %+v", r.Consequence)
	}
	if _, err := NewEngine([]Rule{r}, nil); err != nil {
		t.Errorf("valid rule refused: %v", err)
	}
	r.Consequence = append(r.Consequence, Condition{Arg: "amount", Op: OpGt, Value: 1})
	if _, err := NewEngine([]Rule{r}, nil); err == nil || !strings.Contains(err.Error(), "consequence item 3") {
		t.Errorf("err = %v, want it to name consequence item 3", err)
	}
}

func TestAllowOnListFactWarns(t *testing.T) {
	engine, err := NewEngine([]Rule{
		{Name: "public-data-goes", Tool: "*", Consequence: Conditions{{Arg: FactDataClasses, Op: OpIn, Value: []any{"public"}}}, Action: ActionAllow},
		{Name: "nothing-sensitive-goes", Tool: "*", Consequence: Conditions{{Arg: FactDataClasses, Op: OpNotIn, Value: []any{"payment"}}}, Action: ActionAllow},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := engine.Warnings()
	if len(w) != 1 || !strings.Contains(w[0], `rule "public-data-goes"`) || !strings.Contains(w[0], "not_in") {
		t.Errorf("warnings = %q, want one about public-data-goes", w)
	}
}

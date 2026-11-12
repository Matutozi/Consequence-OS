package policy

import (
	"context"
	"testing"
	"time"
)

func TestPromptNumbers(t *testing.T) {
	tests := []struct {
		text   string
		strict float64 // NaN-free: -1 means "not a number"
		loose  float64
	}{
		{"5000", 5000, 5000},
		{"-12.5", -12.5, -12.5},
		{"007", 7, 7},
		{" 5000", -1, 5000},
		{"5000\n", -1, 5000},
		{"+5000", -1, 5000},
		{"5_000", -1, 5000},
		{"5e3", -1, 5000},
		{"0x1388", -1, 5000},
		{"٥٠٠٠", -1, 5000}, // Arabic-Indic digits, which Python's int reads
		{"５０００", -1, 5000}, // fullwidth
		{"𝟓𝟎𝟎𝟎", -1, 5000}, // mathematical bold, in adjacent runs of ten
		{"5,000", -1, -1},
		{"", -1, -1},
		{"five", -1, -1},
		{".5", -1, 0.5},
		{"5.", -1, 5},
	}
	for _, tt := range tests {
		for _, mode := range []struct {
			loose bool
			want  float64
		}{{false, tt.strict}, {true, tt.loose}} {
			got, ok := promptText(tt.text).number(mode.loose)
			if mode.want == -1 {
				if ok {
					t.Errorf("%q (loose %v) read as %v, want not a number", tt.text, mode.loose, got)
				}
				continue
			}
			if !ok || got != mode.want {
				t.Errorf("%q (loose %v) = %v, %v; want %v", tt.text, mode.loose, got, ok, mode.want)
			}
		}
	}
}

func TestPromptRules(t *testing.T) {
	e, err := NewEngine([]Rule{
		{Name: "big-reports", Tool: "prompt:report", When: Conditions{{Arg: "limit", Op: OpGt, Value: 1000}}, Action: ActionDeny},
		{Name: "small-reports", Tool: "prompt:report", When: Conditions{{Arg: "limit", Op: OpLte, Value: 100}}, Action: ActionAllow},
		{Name: "draft-mode", Tool: "prompt:report", When: Conditions{{Arg: "mode", Op: OpEq, Value: "5"}}, Action: ActionAllow},
		{Name: "big-refunds", Tool: "payments.refund", When: Conditions{{Arg: "amount", Op: OpGt, Value: 1000}}, Action: ActionDeny},
		{Name: "rest", Tool: "*", Action: ActionAsk},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		tool string
		args map[string]any
		rule string
	}{
		{"prompt:report", map[string]any{"limit": "5000"}, "big-reports"},
		{"prompt:report", map[string]any{"limit": " 5000"}, "big-reports"}, // deny reads what a server might
		{"prompt:report", map[string]any{"limit": "5e3"}, "big-reports"},
		{"prompt:report", map[string]any{"limit": "٥٠٠٠"}, "big-reports"},
		{"prompt:report", map[string]any{"Limit": "5000"}, "big-reports"}, // any case of the name, as for tools
		{"prompt:report", map[string]any{"limit": "50"}, "small-reports"},
		{"prompt:report", map[string]any{"limit": " 50"}, "rest"},     // allow needs a plain decimal
		{"prompt:report", map[string]any{"limit": "5e1"}, "rest"},     // so does this
		{"prompt:report", map[string]any{"limit": "lots"}, "rest"},    // not a number at all
		{"prompt:report", map[string]any{"mode": "5"}, "draft-mode"},  // eq compares the text as sent
		{"payments.refund", map[string]any{"amount": "5000"}, "rest"}, // tool arguments keep their JSON types
		{"payments.refund", map[string]any{"amount": 5000.0}, "big-refunds"},
	}
	for _, tt := range tests {
		d, err := e.Decide(context.Background(), Call{AgentID: "a", Tool: tt.tool, Args: tt.args}, NoUsage{})
		if err != nil {
			t.Fatal(err)
		}
		if d.Rule != tt.rule {
			t.Errorf("%s %v: rule %s, want %s", tt.tool, tt.args, d.Rule, tt.rule)
		}
	}
	// A number compared with eq is not the text "5": as sent, it is text.
	e2, _ := NewEngine([]Rule{{Name: "five", Tool: "prompt:*", When: Conditions{{Arg: "n", Op: OpEq, Value: 5}}, Action: ActionDeny}}, nil)
	if d, _ := e2.Decide(context.Background(), Call{Tool: "prompt:x", Args: map[string]any{"n": "5"}}, NoUsage{}); d.Rule == "five" {
		t.Error("eq 5 matched the text \"5\"")
	}
	// The caller's arguments aren't changed.
	args := map[string]any{"limit": "5000"}
	_, _ = e.Decide(context.Background(), Call{Tool: "prompt:report", Args: args}, NoUsage{})
	if _, ok := args["limit"].(string); !ok {
		t.Errorf("Decide changed the caller's arguments: %#v", args)
	}
}

func TestPromptLimits(t *testing.T) {
	e, err := NewEngine([]Rule{
		{Name: "rows-per-day", Tool: "prompt:export", Limit: &Limit{Sum: "rows", Max: 1000, Per: 24 * time.Hour}, Action: ActionDeny},
		{Name: "exports", Tool: "prompt:export", Action: ActionAllow},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	usage := &countingUsage{}
	at := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	for i, s := range []struct {
		rows string
		want Action
	}{{"600", ActionAllow}, {"300", ActionAllow}, {" 200", ActionDeny}, {"100", ActionAllow}, {"1", ActionDeny}} {
		c := Call{AgentID: "a", Tool: "prompt:export", Args: map[string]any{"rows": s.rows}, At: at}
		d, err := e.Decide(context.Background(), c, usage)
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != s.want {
			t.Fatalf("step %d, rows %q: %s, want %s", i+1, s.rows, d.Action, s.want)
		}
		if d.Action == ActionAllow {
			usage.records = append(usage.records, e.UsageRecords(c)...)
		}
	}
	if got := usage.records[0].Values["rows"]; got != 600 {
		t.Errorf("the first export was counted as %v rows, want 600", got)
	}
}

package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// evaluate decides a call with no usage history, at a fixed time.
func evaluate(t *testing.T, e *Engine, tool string, args map[string]any) Decision {
	t.Helper()
	d, err := e.Decide(context.Background(), Call{AgentID: "bot", Tool: tool, Args: args, At: monday10am}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// monday10am is Monday 2 Nov 2026, 10:00 in Lagos (UTC+1).
var monday10am = time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)

// fakeUsage returns fixed totals and remembers what it was asked.
type fakeUsage struct {
	count int
	sum   float64
	err   error
	asked []string // "agent tool since sumArg"
}

func (f *fakeUsage) CountUsage(_ context.Context, agentID, tool string, since time.Time, sumArg string) (int, float64, error) {
	f.asked = append(f.asked, strings.Join([]string{agentID, tool, since.Format(time.RFC3339), sumArg}, " "))
	return f.count, f.sum, f.err
}

func TestSchedules(t *testing.T) {
	officeHours := &Schedule{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Hours: "09:00-17:00", Timezone: "Africa/Lagos"}
	overnight := &Schedule{Hours: "22:00-06:00", Timezone: "UTC"}
	weekend := &Schedule{Days: []string{"sat", "sun"}, Timezone: "UTC"}

	tests := []struct {
		name  string
		rule  Rule
		at    time.Time
		match bool
	}{
		{"during, inside", Rule{During: officeHours}, monday10am, true},
		{"during, start is included", Rule{During: officeHours}, time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC), true},
		{"during, end is excluded", Rule{During: officeHours}, time.Date(2026, 11, 2, 16, 0, 0, 0, time.UTC), false},
		{"during, wrong day", Rule{During: officeHours}, time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC), false},
		{"time zone is applied", Rule{During: officeHours}, time.Date(2026, 11, 2, 7, 30, 0, 0, time.UTC), false}, // 08:30 in Lagos
		{"outside, inside the window", Rule{Outside: officeHours}, monday10am, false},
		{"outside, at night", Rule{Outside: officeHours}, time.Date(2026, 11, 2, 21, 0, 0, 0, time.UTC), true},
		{"past midnight, late", Rule{During: overnight}, time.Date(2026, 11, 2, 23, 0, 0, 0, time.UTC), true},
		{"past midnight, early", Rule{During: overnight}, time.Date(2026, 11, 3, 5, 59, 0, 0, time.UTC), true},
		{"past midnight, daytime", Rule{During: overnight}, time.Date(2026, 11, 3, 6, 0, 0, 0, time.UTC), false},
		{"whole day", Rule{During: weekend}, time.Date(2026, 11, 8, 3, 0, 0, 0, time.UTC), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.rule.Name, tt.rule.Tool, tt.rule.Action = "r", "x", ActionAsk
			e, err := NewEngine([]Rule{tt.rule}, nil)
			if err != nil {
				t.Fatal(err)
			}
			d, err := e.Decide(context.Background(), Call{Tool: "x", At: tt.at}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := d.Rule == "r"; got != tt.match {
				t.Errorf("matched = %v, want %v", got, tt.match)
			}
		})
	}
}

func TestLimits(t *testing.T) {
	tests := []struct {
		name  string
		limit Limit
		args  map[string]any
		usage fakeUsage
		match bool
	}{
		{"count under the limit", Limit{Max: 10, Per: 24 * time.Hour}, nil, fakeUsage{count: 9}, false},
		{"count: the 11th call matches", Limit{Max: 10, Per: 24 * time.Hour}, nil, fakeUsage{count: 10}, true},
		{"sum stays under", Limit{Sum: "amount", Max: 2000, Per: 24 * time.Hour}, map[string]any{"amount": 500.0}, fakeUsage{sum: 1500}, false},
		{"sum would pass the limit", Limit{Sum: "amount", Max: 2000, Per: 24 * time.Hour}, map[string]any{"amount": 500.01}, fakeUsage{sum: 1500}, true},
		{"sum with the amount as text doesn't match", Limit{Sum: "amount", Max: 2000, Per: 24 * time.Hour}, map[string]any{"amount": "9999"}, fakeUsage{sum: 1500}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit := tt.limit
			e, err := NewEngine([]Rule{{Name: "r", Tool: "payments.*", Limit: &limit, Action: ActionAsk}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			d, err := e.Decide(context.Background(), Call{AgentID: "bot", Tool: "payments.refund", Args: tt.args, At: monday10am}, &tt.usage)
			if err != nil {
				t.Fatal(err)
			}
			if got := d.Rule == "r"; got != tt.match {
				t.Errorf("matched = %v, want %v", got, tt.match)
			}
		})
	}
}

func TestLimitAsksAboutTheRightWindow(t *testing.T) {
	e, _ := NewEngine([]Rule{
		{Name: "small", Tool: "payments.refund", When: Conditions{{Arg: "amount", Op: OpLte, Value: 50}}, Action: ActionAllow},
		{Name: "daily-total", Tool: "payments.refund", Limit: &Limit{Sum: "amount", Max: 2000, Per: 24 * time.Hour}, Action: ActionAsk},
	}, nil)
	u := &fakeUsage{}
	ctx := context.Background()

	// A rule that matches before the limit rule means usage is never counted.
	_, _ = e.Decide(ctx, Call{AgentID: "bot", Tool: "payments.refund", Args: map[string]any{"amount": 20.0}, At: monday10am}, u)
	if len(u.asked) != 0 {
		t.Errorf("usage counted although an earlier rule matched: %v", u.asked)
	}
	_, _ = e.Decide(ctx, Call{AgentID: "bot", Tool: "payments.refund", Args: map[string]any{"amount": 900.0}, At: monday10am}, u)
	if want := "bot payments.refund 2026-11-01T09:00:00Z amount"; len(u.asked) != 1 || u.asked[0] != want {
		t.Errorf("asked %v, want [%s]", u.asked, want)
	}

	// If usage can't be counted, there's no decision: the call must not go through.
	u.err = errors.New("db down")
	if _, err := e.Decide(ctx, Call{AgentID: "bot", Tool: "payments.refund", Args: map[string]any{"amount": 900.0}, At: monday10am}, u); err == nil {
		t.Error("expected an error when usage can't be counted")
	}
}

func TestUsageHelpers(t *testing.T) {
	e, _ := NewEngine([]Rule{
		{Name: "count", Tool: "payments.*", Limit: &Limit{Max: 10, Per: time.Hour}, Action: ActionAsk},
		{Name: "total", Tool: "payments.refund", Limit: &Limit{Sum: "amount", Max: 100, Per: 48 * time.Hour}, Action: ActionAsk},
		{Name: "plain", Tool: "notes.read", Action: ActionAllow},
	}, nil)
	if !e.TracksUsage("payments.charge") || e.TracksUsage("notes.read") {
		t.Error("TracksUsage is wrong")
	}
	if got := e.SummedArgs("payments.refund"); len(got) != 1 || got[0] != "amount" {
		t.Errorf("SummedArgs = %v", got)
	}
	if got := e.SummedArgs("payments.charge"); len(got) != 0 {
		t.Errorf("SummedArgs(charge) = %v", got)
	}
	if e.LongestWindow() != 48*time.Hour {
		t.Errorf("LongestWindow = %v", e.LongestWindow())
	}
}

func TestScheduleAndLimitErrors(t *testing.T) {
	tz := "UTC"
	tests := []struct {
		name    string
		rule    Rule
		wantErr string
	}{
		{"both during and outside", Rule{During: &Schedule{Timezone: tz}, Outside: &Schedule{Timezone: tz}}, "not both"},
		{"no timezone", Rule{During: &Schedule{Hours: "09:00-17:00"}}, "timezone is required"},
		{"bad timezone", Rule{During: &Schedule{Timezone: "Mars/Olympus"}}, "unknown timezone"},
		{"bad day", Rule{During: &Schedule{Days: []string{"funday"}, Timezone: tz}}, "unknown day"},
		{"bad hours", Rule{Outside: &Schedule{Hours: "9am to 5pm", Timezone: tz}}, "must look like 09:00-17:00"},
		{"bad clock", Rule{Outside: &Schedule{Hours: "09:00-25:00", Timezone: tz}}, "not a time"},
		{"empty window", Rule{During: &Schedule{Hours: "09:00-09:00", Timezone: tz}}, "same time"},
		{"limit without window", Rule{Limit: &Limit{Max: 1}}, "limit.per"},
		{"limit without max", Rule{Limit: &Limit{Per: time.Hour}}, "limit.max"},
		{"fractional call count", Rule{Limit: &Limit{Max: 2.5, Per: time.Hour}}, "whole number"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.rule.Name, tt.rule.Tool, tt.rule.Action = "r", "x", ActionAsk
			_, err := NewEngine([]Rule{tt.rule}, nil)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestEngineCopiesSchedulesAndLimits(t *testing.T) {
	s := &Schedule{Hours: "09:00-17:00", Timezone: "UTC"}
	l := &Limit{Max: 1, Per: time.Hour}
	e, err := NewEngine([]Rule{{Name: "r", Tool: "x", During: s, Limit: l, Action: ActionDeny}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Hours, l.Max = "00:00-01:00", 1000 // changing the caller's copies must not change the engine
	d, _ := e.Decide(context.Background(), Call{Tool: "x", At: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)}, &fakeUsage{count: 1})
	if d.Rule != "r" {
		t.Errorf("engine was changed through the caller's pointers: %+v", d)
	}
}

func TestLimitString(t *testing.T) {
	tests := map[string]Limit{
		"more than 10 calls per 24h":            {Max: 10, Per: 24 * time.Hour},
		"amount totals more than 500 per 1h30m": {Sum: "amount", Max: 500, Per: 90 * time.Minute},
		"more than 3 calls per 45s":             {Max: 3, Per: 45 * time.Second},
	}
	for want, l := range tests {
		if got := l.String(); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

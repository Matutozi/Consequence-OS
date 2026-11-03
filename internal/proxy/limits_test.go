package proxy

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/store"
)

func refund(amount string) string {
	return call("payments.refund", `{"charge_id":"ch_1","amount":`+amount+`}`)
}

// outcome sends one call and says what happened to it.
func (f fixture) outcome(t *testing.T, body string) string {
	t.Helper()
	before := f.up.count()
	rec := f.do(http.MethodPost, body, nil)
	switch {
	case f.up.count() > before:
		return "forwarded"
	case strings.Contains(rec.Body.String(), "Blocked by ConsequenceOS"):
		return "blocked"
	case strings.Contains(rec.Body.String(), "Approval pending"):
		return "held"
	}
	return "status " + rec.Body.String()
}

func TestCountLimit(t *testing.T) {
	f := newFixtureWithRules(t, nil, []policy.Rule{
		{Name: "refund-burst", Tool: "payments.refund", Limit: &policy.Limit{Max: 2, Per: time.Hour}, Action: policy.ActionDeny},
		{Name: "refunds", Tool: "payments.refund", Action: policy.ActionAllow},
	})
	for i, want := range []string{"forwarded", "forwarded", "blocked"} {
		if got := f.outcome(t, refund("10")); got != want {
			t.Fatalf("call %d: %s, want %s", i+1, got, want)
		}
	}
	// A blocked call isn't forwarded, so it doesn't count; an hour later the window has moved on.
	*f.clock = f.clock.Add(time.Hour)
	if got := f.outcome(t, refund("10")); got != "forwarded" {
		t.Errorf("an hour later: %s, want forwarded", got)
	}
}

func TestSumLimit(t *testing.T) {
	f := newFixtureWithRules(t, nil, []policy.Rule{
		{Name: "daily-total", Tool: "payments.refund", Limit: &policy.Limit{Sum: "amount", Max: 100, Per: 24 * time.Hour}, Action: policy.ActionAsk},
		{Name: "refunds", Tool: "payments.refund", Action: policy.ActionAllow},
	})
	steps := []struct{ amount, want string }{
		{"60", "forwarded"}, // total 60
		{"30", "forwarded"}, // 90
		{"20", "held"},      // would be 110
		{"10", "forwarded"}, // exactly 100 is allowed
		{"0.01", "held"},
	}
	for _, s := range steps {
		if got := f.outcome(t, refund(s.amount)); got != s.want {
			t.Errorf("refund of %s: %s, want %s", s.amount, got, s.want)
		}
	}
}

func TestScheduleRule(t *testing.T) {
	f := newFixtureWithRules(t, nil, []policy.Rule{
		{Name: "after-hours", Tool: "payments.refund", Action: policy.ActionAsk,
			Outside: &policy.Schedule{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Hours: "09:00-17:00", Timezone: "UTC"}},
		{Name: "refunds", Tool: "payments.refund", Action: policy.ActionAllow},
	})
	// The fixture clock starts on Monday 2 Nov 2026 at 10:00 UTC.
	if got := f.outcome(t, refund("10")); got != "forwarded" {
		t.Errorf("office hours: %s, want forwarded", got)
	}
	*f.clock = f.clock.Add(9 * time.Hour) // 19:00
	if got := f.outcome(t, refund("10")); got != "held" {
		t.Errorf("evening: %s, want held", got)
	}
}

func TestParallelCallsCannotSlipUnderALimit(t *testing.T) {
	f := newFixtureWithRules(t, nil, []policy.Rule{
		{Name: "burst", Tool: "payments.refund", Limit: &policy.Limit{Max: 3, Per: time.Hour}, Action: policy.ActionDeny},
		{Name: "refunds", Tool: "payments.refund", Action: policy.ActionAllow},
	})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.do(http.MethodPost, refund("10"), nil)
		}()
	}
	wg.Wait()
	if n := f.up.count(); n != 3 {
		t.Errorf("%d calls forwarded, want exactly 3", n)
	}
}

// failingUsage makes usage lookups fail.
type failingUsage struct{ store.Memory }

func (*failingUsage) CountUsage(context.Context, string, string, time.Time, string) (int, float64, error) {
	return 0, 0, errors.New("db down")
}

func TestFailsClosedWhenUsageUnavailable(t *testing.T) {
	f := newFixtureWithRules(t, &failingUsage{Memory: *store.NewMemory()}, []policy.Rule{
		{Name: "burst", Tool: "payments.refund", Limit: &policy.Limit{Max: 3, Per: time.Hour}, Action: policy.ActionDeny},
		{Name: "refunds", Tool: "payments.refund", Action: policy.ActionAllow},
	})
	rec := f.do(http.MethodPost, refund("10"), nil)
	if rec.Code != http.StatusServiceUnavailable || f.up.count() != 0 {
		t.Errorf("got %d with %d forwarded, want 503 and nothing forwarded", rec.Code, f.up.count())
	}
}

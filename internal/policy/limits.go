package policy

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Limit makes a rule match once a call would take an agent over a limit
// within a rolling window: either a number of calls, or (with Sum) the
// total of one numeric argument across calls.
//
//	limit: { max: 10, per: 24h }               # the 11th call in 24 hours matches
//	limit: { sum: amount, max: 2000, per: 24h } # matches once the day's total would pass 2000
//
// Only calls that were forwarded count, per agent and per tool.
type Limit struct {
	Max float64       `yaml:"max"`
	Per time.Duration `yaml:"per"`
	Sum string        `yaml:"sum,omitempty"` // argument to total; empty counts calls
}

func (l *Limit) validate() error {
	if l.Per <= 0 {
		return errors.New("limit.per must be a positive duration like 24h")
	}
	if l.Max <= 0 {
		return errors.New("limit.max must be positive")
	}
	if l.Sum == "" && l.Max != math.Trunc(l.Max) {
		return errors.New("limit.max must be a whole number when counting calls")
	}
	return nil
}

// UsageCounter reports what an agent has already done. The store implements it.
type UsageCounter interface {
	// CountUsage returns how many forwarded calls agentID made to tool after
	// since (not at it: a window of 1h leaves out a call exactly 1h old), and
	// the total of argument sumArg across them ("" skips the total).
	CountUsage(ctx context.Context, agentID, tool string, since time.Time, sumArg string) (count int, sum float64, err error)
}

// UsageRecord is one forwarded call, saved so limits can count it later.
type UsageRecord struct {
	AgentID string
	Tool    string
	At      time.Time
	Values  map[string]float64 // the numeric arguments some limit sums, e.g. amount
}

// NoUsage is a UsageCounter that has seen nothing, for dry runs like -tool.
type NoUsage struct{}

// CountUsage implements UsageCounter.
func (NoUsage) CountUsage(context.Context, string, string, time.Time, string) (int, float64, error) {
	return 0, 0, nil
}

// exceeded reports whether this call would take the agent over the limit.
func (l *Limit) exceeded(ctx context.Context, c Call, usage UsageCounter) (bool, error) {
	if usage == nil {
		return false, errors.New("policy: a limit rule needs a usage counter")
	}
	var amount float64
	if l.Sum != "" {
		v, ok := toNumber(c.Args[l.Sum])
		if !ok {
			return false, nil // like a condition: a missing or non-numeric argument doesn't match
		}
		amount = v
	}
	count, sum, err := usage.CountUsage(ctx, c.AgentID, c.Tool, c.At.Add(-l.Per), l.Sum)
	if err != nil {
		return false, fmt.Errorf("policy: count usage: %w", err)
	}
	if l.Sum == "" {
		return float64(count+1) > l.Max, nil
	}
	return sum+amount > l.Max, nil
}

func (l *Limit) String() string {
	if l.Sum == "" {
		return fmt.Sprintf("more than %g calls per %s", l.Max, shortDuration(l.Per))
	}
	return fmt.Sprintf("%s totals more than %g per %s", l.Sum, l.Max, shortDuration(l.Per))
}

// shortDuration prints 24h rather than Go's 24h0m0s.
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

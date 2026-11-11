// Package policy decides whether a tool call is allowed, needs a human, or is denied.
package policy

import (
	"context"
	"fmt"
	"slices"
	"time"
)

// Action is what a rule tells the proxy to do with a call.
type Action string

const (
	ActionAllow Action = "allow"
	ActionAsk   Action = "ask"
	ActionDeny  Action = "deny"
)

// DefaultRule is the rule name reported when no configured rule matched.
const DefaultRule = "default"

// Rule matches tool calls by tool name (glob allowed). Everything else it
// sets must hold too: the argument conditions, the time window, and the limit.
type Rule struct {
	Name    string     `yaml:"name"`
	Tool    string     `yaml:"tool"`
	When    Conditions `yaml:"when,omitempty"`    // nil means "no conditions"
	During  *Schedule  `yaml:"during,omitempty"`  // only inside this window
	Outside *Schedule  `yaml:"outside,omitempty"` // only outside this window
	Limit   *Limit     `yaml:"limit,omitempty"`   // only once this call would pass the limit
	Action  Action     `yaml:"action"`
}

// Call is one tool call to decide on.
type Call struct {
	AgentID string
	Tool    string
	Args    map[string]any
	At      time.Time // when the call arrived; schedules and limits use it
}

// Decision is the outcome of evaluating one tool call.
type Decision struct {
	Action Action
	Rule   string // name of the matching rule, or DefaultRule
	Level  Level
}

// Engine evaluates rules top to bottom; the first match wins.
type Engine struct {
	rules  []Rule
	levels Levels
}

// NewEngine validates the rules and levels and returns an engine.
func NewEngine(rules []Rule, levels Levels) (*Engine, error) {
	if err := levels.Validate(); err != nil {
		return nil, err
	}
	e := &Engine{
		rules:  make([]Rule, len(rules)),
		levels: make(Levels, len(levels)),
	}
	seen := make(map[string]bool, len(rules))
	for i, r := range rules {
		// Work on a copy so later changes to the caller's rules can't affect
		// us. Copying a struct copies only pointers and slice headers, so
		// copy what they point at too.
		r = copyRule(r)
		if err := validateRule(&r); err != nil {
			return nil, fmt.Errorf("rule %d (%q): %w", i+1, r.Name, err)
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("rule %d: duplicate name %q", i+1, r.Name)
		}
		seen[r.Name] = true
		e.rules[i] = r
	}
	for tool, level := range levels {
		e.levels[tool] = level
	}
	return e, nil
}

func copyRule(r Rule) Rule {
	r.When = append(Conditions(nil), r.When...)
	if r.During != nil {
		d := *r.During
		r.During = &d
	}
	if r.Outside != nil {
		o := *r.Outside
		r.Outside = &o
	}
	if r.Limit != nil {
		l := *r.Limit
		r.Limit = &l
	}
	return r
}

// validateRule checks a rule and compiles its schedules.
func validateRule(r *Rule) error {
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	if r.Name == DefaultRule {
		return fmt.Errorf("name %q is reserved", DefaultRule)
	}
	if r.Tool == "" {
		return fmt.Errorf("tool is required")
	}
	if !validPattern(r.Tool) {
		return fmt.Errorf("bad tool pattern %q", r.Tool)
	}
	switch r.Action {
	case ActionAllow, ActionAsk, ActionDeny:
	default:
		return fmt.Errorf("unknown action %q (want allow, ask or deny)", r.Action)
	}
	if r.During != nil && r.Outside != nil {
		return fmt.Errorf("use during or outside, not both")
	}
	for name, s := range map[string]*Schedule{"during": r.During, "outside": r.Outside} {
		if s != nil {
			if err := s.compile(); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if r.Limit != nil {
		if err := r.Limit.validate(); err != nil {
			return err
		}
	}
	return r.When.validate()
}

// Decide picks the action for a call. usage answers limit rules and may be
// nil when no rule has a limit. An error means usage couldn't be counted;
// the caller must not forward the call.
func (e *Engine) Decide(ctx context.Context, c Call, usage UsageCounter) (Decision, error) {
	level := e.levels.For(c.Tool)
	for i := range e.rules {
		matched, err := e.rules[i].matches(ctx, c, usage)
		if err != nil {
			return Decision{}, fmt.Errorf("rule %q: %w", e.rules[i].Name, err)
		}
		if matched {
			return Decision{Action: e.rules[i].Action, Rule: e.rules[i].Name, Level: level}, nil
		}
	}
	return Decision{Action: defaultAction(level), Rule: DefaultRule, Level: level}, nil
}

// matches checks the cheap parts first, so usage is only counted when the
// tool, time and arguments already fit.
func (r *Rule) matches(ctx context.Context, c Call, usage UsageCounter) (bool, error) {
	switch {
	case !matchTool(r.Tool, c.Tool):
		return false, nil
	case r.During != nil && !r.During.contains(c.At):
		return false, nil
	case r.Outside != nil && r.Outside.contains(c.At):
		return false, nil
	case !r.When.matches(c.Args):
		return false, nil
	case r.Limit == nil:
		return true, nil
	}
	return r.Limit.exceeded(ctx, r.Tool, c, usage)
}

// UsageScopes lists the scopes whose limits cover tool: the tool patterns of
// its limit rules, sorted and without repeats. A forwarded call counts in
// every one, so a call to payments.refund counts towards limits on both
// payments.refund and payments.*. Empty when no limit covers tool.
func (e *Engine) UsageScopes(tool string) []string {
	var scopes []string
	for _, r := range e.rules {
		if r.Limit != nil && matchTool(r.Tool, tool) && !slices.Contains(scopes, r.Tool) {
			scopes = append(scopes, r.Tool)
		}
	}
	slices.Sort(scopes)
	return scopes
}

// UsageRecords describes a forwarded call for the usage log: one record per
// scope, keeping only the numeric arguments that scope's limits add up.
// Negative values are kept as 0, so no call can lower a total.
func (e *Engine) UsageRecords(c Call) []UsageRecord {
	scopes := e.UsageScopes(c.Tool)
	records := make([]UsageRecord, 0, len(scopes))
	for _, scope := range scopes {
		u := UsageRecord{AgentID: c.AgentID, Tool: scope, At: c.At}
		for _, r := range e.rules {
			if r.Limit == nil || r.Limit.Sum == "" || r.Tool != scope {
				continue
			}
			if v, ok := toNumber(c.Args[r.Limit.Sum]); ok {
				if u.Values == nil {
					u.Values = map[string]float64{}
				}
				u.Values[r.Limit.Sum] = max(v, 0)
			}
		}
		records = append(records, u)
	}
	return records
}

// LongestWindow is the longest limit window, i.e. how long usage records
// must be kept. Zero when no rule has a limit.
func (e *Engine) LongestWindow() time.Duration {
	var longest time.Duration
	for _, r := range e.rules {
		if r.Limit != nil && r.Limit.Per > longest {
			longest = r.Limit.Per
		}
	}
	return longest
}

// LevelFor returns the configured level of a tool.
func (e *Engine) LevelFor(tool string) Level {
	return e.levels.For(tool)
}

func defaultAction(level Level) Action {
	if level == LevelRead {
		return ActionAllow
	}
	return ActionAsk
}

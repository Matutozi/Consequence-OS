// Package policy decides whether a tool call is allowed, needs a human, or is denied.
package policy

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/matutozi/consequence-os/internal/consequence"
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

// DefaultAllowBelow is the score under which a call no rule matched is
// allowed; at or above it, the call asks. With the default scores, reads
// (0) are allowed and everything else (40 and up) asks.
const DefaultAllowBelow = 20

// Rule matches tool calls by tool name (glob allowed). Everything else it
// sets must hold too: the agents, the argument conditions, the consequence
// conditions, the time window, and the limit.
type Rule struct {
	Name string `yaml:"name"`
	Tool string `yaml:"tool"`
	// Agents limits the rule to calls from these agents, by ID: a role,
	// such as only the results officer may transmit results. Empty means
	// every agent. IDs are compared exactly; an agent's ID comes from the
	// key it authenticates with, not from anything it sends.
	Agents []string   `yaml:"agents,omitempty"`
	When   Conditions `yaml:"when,omitempty"` // nil means "no conditions"
	// Consequence holds conditions on the call's assessment, written like
	// When, with a fact as the arg: { arg: score, op: gte, value: 70 }.
	Consequence Conditions `yaml:"consequence,omitempty"`
	During      *Schedule  `yaml:"during,omitempty"`  // only inside this window
	Outside     *Schedule  `yaml:"outside,omitempty"` // only outside this window
	Limit       *Limit     `yaml:"limit,omitempty"`   // only once this call would pass the limit
	Action      Action     `yaml:"action"`
}

// Call is one tool call to decide on.
type Call struct {
	AgentID string
	Tool    string
	Args    map[string]any
	At      time.Time // when the call arrived; schedules and limits use it
	// Consequence is what the call would affect. Left unset, the engine
	// assesses it from the tools map, so it is never taken as harmless.
	Consequence consequence.Assessment
}

// Decision is the outcome of evaluating one tool call.
type Decision struct {
	Action      Action
	Rule        string // name of the matching rule, or DefaultRule
	Level       Level  // derived from the assessment's reversibility
	Consequence consequence.Assessment
}

// Engine evaluates rules top to bottom; the first match wins.
type Engine struct {
	rules      []Rule
	levels     Levels
	static     consequence.Static
	allowBelow int
}

// Option changes how an engine decides.
type Option func(*Engine)

// AllowBelow sets the score under which a call no rule matched is allowed.
// 0 means no call is allowed by default. NewEngine checks the range.
func AllowBelow(score int) Option {
	return func(e *Engine) { e.allowBelow = score }
}

// NewEngine validates the rules and levels and returns an engine.
func NewEngine(rules []Rule, levels Levels, opts ...Option) (*Engine, error) {
	if err := levels.Validate(); err != nil {
		return nil, err
	}
	e := &Engine{
		rules:      make([]Rule, len(rules)),
		levels:     make(Levels, len(levels)),
		allowBelow: DefaultAllowBelow,
	}
	for _, opt := range opts {
		opt(e)
	}
	if e.allowBelow < 0 || e.allowBelow > consequence.MaxScore {
		return nil, fmt.Errorf("default_allow_below must be from 0 to %d, not %d", consequence.MaxScore, e.allowBelow)
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
	tools := make(map[string]consequence.Reversibility, len(levels))
	for tool, level := range levels {
		e.levels[tool] = level
		tools[tool] = level.Reversibility()
	}
	e.static = consequence.NewStatic(tools)
	return e, nil
}

// Static is the resolver built from the tools map. The proxy uses it
// unless it is given another, and the engine falls back on it.
func (e *Engine) Static() consequence.Static { return e.static }

func copyRule(r Rule) Rule {
	r.Agents = append([]string(nil), r.Agents...)
	r.When = append(Conditions(nil), r.When...)
	r.Consequence = append(Conditions(nil), r.Consequence...)
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
	for i, a := range r.Agents {
		if strings.TrimSpace(a) == "" {
			return fmt.Errorf("agents: entry %d is empty", i+1)
		}
		if slices.Contains(r.Agents[:i], a) {
			return fmt.Errorf("agents: %q is listed twice", a)
		}
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
	if err := r.When.validate("when"); err != nil {
		return err
	}
	return validateFacts(r.Consequence)
}

// Decide picks the action for a call. usage answers limit rules and may be
// nil when no rule has a limit. An error means the call's assessment is
// invalid or usage couldn't be counted; the caller must not forward the call.
func (e *Engine) Decide(ctx context.Context, c Call, usage UsageCounter) (Decision, error) {
	if c.Consequence.IsZero() {
		// Assessed on the arguments as sent, before prompt text is wrapped.
		c.Consequence, _ = e.static.Assess(ctx, c.Tool, c.Args) // Static never fails
	} else if err := c.Consequence.Validate(); err != nil {
		return Decision{}, err
	}
	d := Decision{Level: LevelOf(c.Consequence.Reversibility), Consequence: c.Consequence}
	if IsPrompt(c.Tool) {
		c.Args = promptArgs(c.Args) // see prompt.go
	}
	for i := range e.rules {
		matched, err := e.rules[i].matches(ctx, c, usage)
		if err != nil {
			return Decision{}, fmt.Errorf("rule %q: %w", e.rules[i].Name, err)
		}
		if matched {
			d.Action, d.Rule = e.rules[i].Action, e.rules[i].Name
			return d, nil
		}
	}
	d.Action, d.Rule = ActionAsk, DefaultRule
	if c.Consequence.Score < e.allowBelow {
		d.Action = ActionAllow
	}
	return d, nil
}

// matches checks the cheap parts first, so usage is only counted when the
// tool, time and arguments already fit.
func (r *Rule) matches(ctx context.Context, c Call, usage UsageCounter) (bool, error) {
	// Only an allow rule needs exact argument names: for deny and ask, a
	// name in another letter case must match too, or it would slip past.
	loose := r.Action != ActionAllow
	switch {
	case !matchTool(r.Tool, c.Tool):
		return false, nil
	case len(r.Agents) > 0 && !slices.Contains(r.Agents, c.AgentID):
		return false, nil
	case r.During != nil && !r.During.contains(c.At):
		return false, nil
	case r.Outside != nil && r.Outside.contains(c.At):
		return false, nil
	case !r.When.matches(c.Args, loose):
		return false, nil
	case !r.Consequence.matchFacts(c.Consequence):
		return false, nil
	case r.Limit == nil:
		return true, nil
	}
	return r.Limit.exceeded(ctx, r.Tool, c, usage, loose)
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
	if IsPrompt(c.Tool) {
		c.Args = promptArgs(c.Args) // counted as Decide read them; see prompt.go
	}
	records := make([]UsageRecord, 0, len(scopes))
	for _, scope := range scopes {
		u := UsageRecord{AgentID: c.AgentID, Tool: scope, At: c.At}
		for _, r := range e.rules {
			if r.Limit == nil || r.Limit.Sum == "" || r.Tool != scope {
				continue
			}
			// Counted by any letter case of the name, and the largest if
			// there are several: over-counting is the safe way round. A
			// path with * counts every item.
			if v, _, ok := limitAmount(c.Args, r.Limit.Sum, true); ok {
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

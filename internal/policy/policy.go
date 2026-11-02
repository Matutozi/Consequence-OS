// Package policy decides whether a tool call is allowed, needs a human, or is denied.
package policy

import "fmt"

// Action is what a rule tells the proxy to do with a call.
type Action string

const (
	ActionAllow Action = "allow"
	ActionAsk   Action = "ask"
	ActionDeny  Action = "deny"
)

// DefaultRule is the rule name reported when no configured rule matched.
const DefaultRule = "default"

// Rule matches tool calls by tool name (glob allowed) and optional
// argument conditions, all of which must hold.
type Rule struct {
	Name   string     `yaml:"name"`
	Tool   string     `yaml:"tool"`
	When   Conditions `yaml:"when,omitempty"` // nil means "no conditions"
	Action Action     `yaml:"action"`
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
	seen := make(map[string]bool, len(rules))
	for i, r := range rules {
		if err := validateRule(r); err != nil {
			return nil, fmt.Errorf("rule %d (%q): %w", i+1, r.Name, err)
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("rule %d: duplicate name %q", i+1, r.Name)
		}
		seen[r.Name] = true
	}

	// Copy so later changes to the caller's slices or map can't affect us.
	// Copying a struct copies only the slice header, so When is copied too.
	e := &Engine{
		rules:  make([]Rule, len(rules)),
		levels: make(Levels, len(levels)),
	}
	for i, r := range rules {
		r.When = append(Conditions(nil), r.When...)
		e.rules[i] = r
	}
	for tool, level := range levels {
		e.levels[tool] = level
	}
	return e, nil
}

func validateRule(r Rule) error {
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
	return r.When.validate()
}

// Evaluate decides what to do with a call to tool with the given arguments.
func (e *Engine) Evaluate(tool string, args map[string]any) Decision {
	level := e.levels.For(tool)
	for _, r := range e.rules {
		if !matchTool(r.Tool, tool) {
			continue
		}
		if !r.When.matches(args) {
			continue
		}
		return Decision{Action: r.Action, Rule: r.Name, Level: level}
	}
	return Decision{Action: defaultAction(level), Rule: DefaultRule, Level: level}
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

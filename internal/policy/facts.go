package policy

import (
	"fmt"
	"slices"

	"github.com/matutozi/consequence-os/internal/consequence"
)

// The facts a rule's consequence conditions can name.
const (
	FactScore         = "score"
	FactReversibility = "reversibility"
	FactBlastRadius   = "blast_radius"
	FactSource        = "source"
	FactDataClasses   = "data_classes"
	FactOwners        = "owners"
	FactTargets       = "targets"
)

type factKind int

const (
	numberFact factKind = iota
	textFact
	listFact // a list of text; eq and in match when any item does
)

var factKinds = map[string]factKind{
	FactScore: numberFact, FactBlastRadius: numberFact,
	FactReversibility: textFact, FactSource: textFact,
	FactDataClasses: listFact, FactOwners: listFact, FactTargets: listFact,
}

// validateFacts checks a rule's consequence conditions: each must name a
// known fact and compare it in a way that fits.
func validateFacts(conds Conditions) error {
	return conds.each("consequence", validateFact)
}

func validateFact(c Condition) error {
	kind, ok := factKinds[c.Arg]
	if !ok {
		return fmt.Errorf("consequence: unknown fact %q (want score, reversibility, blast_radius, source, data_classes, owners or targets)", c.Arg)
	}
	if err := c.validate(); err != nil {
		return err
	}
	if kind == numberFact {
		if !c.comparesNumber() {
			return fmt.Errorf("consequence: %s is a number, so the value must be one", c.Arg)
		}
		return nil
	}
	if !c.comparesText() {
		return fmt.Errorf("consequence: %s is text, so compare it with eq, ne, in or not_in and text values", c.Arg)
	}
	for _, v := range c.textValues() {
		switch {
		case c.Arg == FactReversibility && !consequence.Reversibility(v).Valid():
			return fmt.Errorf(`consequence: unknown reversibility %q (want read, reversible, compensable or none; "irreversible" is none)`, v)
		case c.Arg == FactSource && v != consequence.SourceConfig && v != consequence.SourceMap:
			return fmt.Errorf("consequence: unknown source %q (want config or map)", v)
		}
	}
	return nil
}

// comparesNumber reports whether the condition's value is numeric. For in
// and not_in that's the first item; validateList keeps them all one kind.
func (c Condition) comparesNumber() bool {
	v := c.Value
	if items, ok := v.([]any); ok && len(items) > 0 {
		v = items[0]
	}
	_, ok := toNumber(v)
	return ok
}

// textValues lists the condition's text values, for checking them.
func (c Condition) textValues() []string {
	var out []string
	if s, ok := c.Value.(string); ok {
		return []string{s}
	}
	items, _ := c.Value.([]any)
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// fact returns the named fact of a, or ok=false when it's missing. A
// blast radius of 0 means unknown and an empty list means none were
// found, so both are missing: a missing fact never matches, as a missing
// argument never does.
func fact(a consequence.Assessment, name string) (v any, ok bool) {
	switch name {
	case FactScore:
		return float64(a.Score), true
	case FactBlastRadius:
		return float64(a.BlastRadius), a.BlastRadius > 0
	case FactReversibility:
		return string(a.Reversibility), true
	case FactSource:
		return a.Source, true
	case FactDataClasses:
		return a.DataClasses, len(a.DataClasses) > 0
	case FactOwners:
		return a.Owners, len(a.Owners) > 0
	case FactTargets:
		return a.Targets, len(a.Targets) > 0
	}
	return nil, false
}

// matchFacts reports whether every condition holds for the assessment.
// An empty list always matches.
func (c Conditions) matchFacts(a consequence.Assessment) bool {
	for _, cond := range c {
		if !cond.matchFact(a) {
			return false
		}
	}
	return true
}

// matchFact checks one condition. On a list fact, eq and in match when any
// item does, and ne and not_in when no item does. So
// { arg: data_classes, op: in, value: [payment] } matches every call that
// touches payment data, whatever else it touches.
func (c Condition) matchFact(a consequence.Assessment) bool {
	v, ok := fact(a, c.Arg)
	if !ok {
		return false
	}
	items, isList := v.([]string)
	if !isList {
		return c.matches(map[string]any{c.Arg: v})
	}
	positive := c
	switch c.Op {
	case OpNe:
		positive.Op = OpEq
	case OpNotIn:
		positive.Op = OpIn
	}
	hit := slices.ContainsFunc(items, func(item string) bool {
		return positive.matches(map[string]any{c.Arg: item})
	})
	if positive.Op == c.Op {
		return hit
	}
	return !hit
}

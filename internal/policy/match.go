package policy

import (
	"encoding/json"
	"fmt"
	"path"
)

// Op is a comparison operator used in a rule's "when" condition.
type Op string

const (
	OpEq  Op = "eq"
	OpNe  Op = "ne"
	OpGt  Op = "gt"
	OpGte Op = "gte"
	OpLt  Op = "lt"
	OpLte Op = "lte"
	// OpIn and OpNotIn compare against a list, e.g. value: [USD, EUR].
	OpIn    Op = "in"
	OpNotIn Op = "not_in"
)

// Condition compares one top-level tool argument against a fixed value,
// e.g. { arg: amount, op: lte, value: 50 } or { arg: currency, op: in, value: [USD, EUR] }.
type Condition struct {
	Arg   string `yaml:"arg"`
	Op    Op     `yaml:"op"`
	Value any    `yaml:"value"`
}

func (c Condition) validate() error {
	if c.Arg == "" {
		return fmt.Errorf("condition: arg is required")
	}
	switch c.Op {
	case OpEq, OpNe:
		if !isScalar(c.Value) {
			return fmt.Errorf("condition on %q: value must be a number, string or bool", c.Arg)
		}
	case OpGt, OpGte, OpLt, OpLte:
		if _, ok := toNumber(c.Value); !ok {
			return fmt.Errorf("condition on %q: op %q needs a numeric value", c.Arg, c.Op)
		}
	case OpIn, OpNotIn:
		if err := validateList(c.Value); err != nil {
			return fmt.Errorf("condition on %q: op %q %w", c.Arg, c.Op, err)
		}
	default:
		return fmt.Errorf("condition on %q: unknown op %q (want eq, ne, gt, gte, lt, lte, in, not_in)", c.Arg, c.Op)
	}
	return nil
}

// validateList checks that v is a non-empty list whose items are all numbers,
// all strings, or all bools. Mixing kinds would make not_in ambiguous.
func validateList(v any) error {
	items, ok := v.([]any) // YAML decodes a sequence into []any
	if !ok || len(items) == 0 {
		return fmt.Errorf("needs a non-empty list value")
	}
	for _, item := range items {
		if !isScalar(item) {
			return fmt.Errorf("list items must be numbers, strings or bools")
		}
		if !sameKind(item, items[0]) {
			return fmt.Errorf("list items must all be the same kind")
		}
	}
	return nil
}

// matches reports whether the condition holds for args. A missing argument or
// one of the wrong type never matches, so evaluation falls through to later rules.
func (c Condition) matches(args map[string]any) bool {
	got, ok := args[c.Arg]
	if !ok {
		return false
	}
	switch c.Op {
	case OpEq:
		return equal(got, c.Value)
	case OpNe:
		// ne still requires comparable types: a string is not "not equal" to 50.
		return sameKind(got, c.Value) && !equal(got, c.Value)
	case OpIn:
		return inList(got, c.Value.([]any))
	case OpNotIn:
		// Like ne: an argument of the wrong kind is not "not in" the list.
		items := c.Value.([]any)
		return sameKind(got, items[0]) && !inList(got, items)
	}

	a, okA := toNumber(got)
	b, okB := toNumber(c.Value)
	if !okA || !okB {
		return false
	}
	switch c.Op {
	case OpGt:
		return a > b
	case OpGte:
		return a >= b
	case OpLt:
		return a < b
	case OpLte:
		return a <= b
	}
	return false
}

// matchTool reports whether tool matches a glob pattern such as "db.delete*".
// Patterns are checked when the engine is built, so the error is ignored here.
func matchTool(pattern, tool string) bool {
	ok, _ := path.Match(pattern, tool)
	return ok
}

func validPattern(pattern string) bool {
	// path.Match only reports a bad pattern when it actually parses it,
	// so matching against an empty string is the cheap way to check.
	_, err := path.Match(pattern, "")
	return err == nil
}

func inList(v any, items []any) bool {
	for _, item := range items {
		if equal(v, item) {
			return true
		}
	}
	return false
}

func equal(a, b any) bool {
	if x, ok := toNumber(a); ok {
		y, ok := toNumber(b)
		return ok && x == y
	}
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	}
	return false
}

func sameKind(a, b any) bool {
	_, numA := toNumber(a)
	_, numB := toNumber(b)
	if numA || numB {
		return numA && numB
	}
	switch a.(type) {
	case string:
		_, ok := b.(string)
		return ok
	case bool:
		_, ok := b.(bool)
		return ok
	}
	return false
}

func isScalar(v any) bool {
	if _, ok := toNumber(v); ok {
		return true
	}
	switch v.(type) {
	case string, bool:
		return true
	}
	return false
}

// toNumber converts the numeric types produced by the YAML and JSON decoders
// into a float64. Go has no common "number" interface, hence the type switch.
func toNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

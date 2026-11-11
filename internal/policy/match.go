package policy

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
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
	// OpLike and OpNotLike match text against a glob, or a list of globs,
	// e.g. value: "git status*" or value: ["*/.env", "*/.env.*"]. The globs
	// follow the rules for tool patterns: * matches any run of characters
	// and ? any one, "/" included.
	OpLike    Op = "like"
	OpNotLike Op = "not_like"
)

// Condition compares one top-level tool argument against a fixed value,
// e.g. { arg: amount, op: lte, value: 50 } or { arg: currency, op: in, value: [USD, EUR] }.
//
// Text is compared exactly unless Fold is set. With fold: true, outer spaces
// are ignored and letter case doesn't matter, so "Production " matches
// "production". Use it on deny and ask rules, which an unexpected spelling
// would otherwise skip.
type Condition struct {
	Arg   string `yaml:"arg"`
	Op    Op     `yaml:"op"`
	Value any    `yaml:"value"`
	Fold  bool   `yaml:"fold,omitempty"`
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
	case OpLike, OpNotLike:
		if err := validatePatterns(c.Value); err != nil {
			return fmt.Errorf("condition on %q: op %q %w", c.Arg, c.Op, err)
		}
	default:
		return fmt.Errorf("condition on %q: unknown op %q (want eq, ne, gt, gte, lt, lte, in, not_in, like, not_like)", c.Arg, c.Op)
	}
	if c.Fold && !c.comparesText() {
		return fmt.Errorf("condition on %q: fold works only with eq, ne, in, not_in, like or not_like and a text value", c.Arg)
	}
	return nil
}

// validatePatterns checks that v is a glob, or a non-empty list of globs.
func validatePatterns(v any) error {
	items, isList := v.([]any)
	if !isList {
		items = []any{v}
	}
	if len(items) == 0 {
		return fmt.Errorf("needs a glob or a list of globs")
	}
	for _, item := range items {
		p, ok := item.(string)
		if !ok || p == "" {
			return fmt.Errorf("needs a glob or a list of globs, like \"git status*\"")
		}
		if !validPattern(p) {
			return fmt.Errorf("pattern %q is not a valid glob", p)
		}
	}
	return nil
}

// patterns returns a like or not_like condition's globs.
func (c Condition) patterns() []string {
	if p, ok := c.Value.(string); ok {
		return []string{p}
	}
	items, _ := c.Value.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.(string)) // validatePatterns checked each is text
	}
	return out
}

// comparesText reports whether the condition compares against text: eq or
// ne with a string, or in or not_in with a list of strings.
func (c Condition) comparesText() bool {
	switch c.Op {
	case OpEq, OpNe:
		_, ok := c.Value.(string)
		return ok
	case OpIn, OpNotIn:
		items, ok := c.Value.([]any)
		if !ok || len(items) == 0 {
			return false
		}
		_, ok = items[0].(string) // validateList keeps every item the same kind
		return ok
	case OpLike, OpNotLike:
		return true // validatePatterns accepts only text
	}
	return false
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

// matches reports whether the condition holds for args, by the argument's
// exact name. A missing argument or one of the wrong type never matches, so
// evaluation falls through to later rules.
func (c Condition) matches(args map[string]any) bool {
	got, ok := args[c.Arg]
	return ok && c.matchValue(got)
}

// matchesLoosely is matches, but an argument whose name differs only in
// letter case counts too: "Environment" for a condition on "environment".
// Many tool servers read names that way (Go's JSON decoding does, for one),
// so a deny rule that missed "Environment" would let the server act on it.
// Deny and ask rules match loosely; allow rules don't, so a variant falls
// through and asks. Either way a variant can only make the policy stricter.
func (c Condition) matchesLoosely(args map[string]any) bool {
	for _, v := range values(args, c.Arg) {
		if c.matchValue(v) {
			return true
		}
	}
	return false
}

// values returns the argument called name, and any whose name differs only
// in letter case. The proxy refuses requests with two such names, so there
// is at most one there; a dry run with -tool might pass several.
func values(args map[string]any, name string) []any {
	var out []any
	for k, v := range args {
		if k == name || strings.EqualFold(k, name) {
			out = append(out, v)
		}
	}
	return out
}

// matchValue compares one argument value with the condition.
func (c Condition) matchValue(got any) bool {
	switch c.Op {
	case OpEq:
		return equal(got, c.Value, c.Fold)
	case OpNe:
		// ne still requires comparable types: a string is not "not equal" to 50.
		return sameKind(got, c.Value) && !equal(got, c.Value, c.Fold)
	case OpIn:
		return inList(got, c.Value.([]any), c.Fold)
	case OpNotIn:
		// Like ne: an argument of the wrong kind is not "not in" the list.
		items := c.Value.([]any)
		return sameKind(got, items[0]) && !inList(got, items, c.Fold)
	case OpLike:
		s, ok := globText(got)
		return ok && c.like(s)
	case OpNotLike:
		// Like ne: an argument that isn't text is not "not like" anything.
		s, ok := globText(got)
		return ok && !c.like(s)
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
//
// In path.Match, * and ? never match "/". Tool names have no slashes, but
// resource URIs are full of them, so "resource:*" or a catch-all "*" would
// miss nearly every read and let it fall through to the default. To make *
// and ? match "/" as well, both sides swap "/" for NUL first. NUL can't
// clash: NewEngine refuses it in patterns, and the proxy in names.
func matchTool(pattern, tool string) bool {
	ok, _ := path.Match(slashless(pattern), slashless(tool))
	return ok
}

func validPattern(pattern string) bool {
	if strings.ContainsRune(pattern, 0) {
		return false
	}
	// path.Match only reports a bad pattern when it actually parses it,
	// so matching against an empty string is the cheap way to check.
	_, err := path.Match(slashless(pattern), "")
	return err == nil
}

// slashless replaces "/" with NUL. It doesn't copy a string with no slashes.
func slashless(s string) string {
	return strings.ReplaceAll(s, "/", "\x00")
}

// like reports whether s matches any of the condition's globs. With fold,
// outer spaces are ignored and letter case doesn't matter.
func (c Condition) like(s string) bool {
	if c.Fold {
		s = strings.ToLower(strings.TrimSpace(s))
	}
	for _, p := range c.patterns() {
		if c.Fold {
			p = strings.ToLower(strings.TrimSpace(p))
		}
		if matchTool(p, s) {
			return true
		}
	}
	return false
}

// globText returns v as text a glob can be matched against. Text holding
// a NUL character doesn't count: matching swaps "/" for NUL (see
// matchTool), so a NUL in the value could stand in for a "/" in the glob.
func globText(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || strings.ContainsRune(s, 0) {
		return "", false
	}
	return s, true
}

func inList(v any, items []any, fold bool) bool {
	for _, item := range items {
		if equal(v, item, fold) {
			return true
		}
	}
	return false
}

// equal compares two scalars of the same kind. With fold, text is compared
// without outer spaces and without regard to letter case.
func equal(a, b any, fold bool) bool {
	if x, ok := toNumber(a); ok {
		y, ok := toNumber(b)
		return ok && x == y
	}
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		if ok && fold {
			return strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(y))
		}
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

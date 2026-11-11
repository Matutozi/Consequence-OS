package policy

import (
	"fmt"
	"strings"
)

// Warnings points out rules that are valid but likely to let through more
// than their author meant. consequenced -check prints them and the server
// logs them at startup; they never stop the config from loading.
//
// There are two kinds. First, a deny or ask rule that depends on text being
// written exactly. "Production", "prod" or "production " skip a rule on
// "production", and the call goes on to later rules, perhaps to an allow.
// An allow rule that depends on exact text is fine: a variant fails closed.
//
// Second, an allow rule that matches a list fact with eq or in. Those match
// when any item does, so a call touching public data and payment data is
// allowed by a rule meant for public data.
func (e *Engine) Warnings() []string {
	var warnings []string
	for _, r := range e.rules {
		if r.Action != ActionAllow {
			continue
		}
		for _, c := range r.Consequence {
			if factKinds[c.Arg] == listFact && (c.Op == OpEq || c.Op == OpIn) {
				warnings = append(warnings, fmt.Sprintf(
					"rule %q: allow matches %s when any one of them is %s, so a call that also touches others is allowed too. "+
						"To allow only calls that touch none of the others, use not_in with the ones you don't allow.",
					r.Name, c.Arg, formatList(c.Value)))
			}
		}
	}
	for i, r := range e.rules {
		if r.Action != ActionDeny && r.Action != ActionAsk {
			continue
		}
		args := exactTextArgs(r.When)
		if len(args) == 0 {
			continue
		}
		next := "later rules"
		if catchAll := e.laterCatchAllAllow(i); catchAll != "" {
			next = fmt.Sprintf("rule %q, which allows it", catchAll)
		}
		warnings = append(warnings, fmt.Sprintf(
			"rule %q: %s matches %s only when it is written exactly, so a variant falls through to %s. "+
				"Add fold: true to the condition, or allow the values you trust and let the rest ask.",
			r.Name, r.Action, strings.Join(args, " and "), next))
	}
	return warnings
}

// exactTextArgs names the arguments that conditions match with eq or in
// against text, without fold. (ne and not_in fail closed: a variant still
// counts as "not equal".)
func exactTextArgs(conds Conditions) []string {
	var args []string
	for _, c := range conds {
		if !c.Fold && (c.Op == OpEq || c.Op == OpIn) && c.comparesText() {
			args = append(args, c.Arg)
		}
	}
	return args
}

// laterCatchAllAllow returns the name of the first rule after rule i that
// allows every call to an overlapping tool, with no conditions, schedule or
// limit, or "" if there is none.
func (e *Engine) laterCatchAllAllow(i int) string {
	tool := e.rules[i].Tool
	for _, r := range e.rules[i+1:] {
		catchAll := len(r.When) == 0 && len(r.Consequence) == 0 && r.During == nil && r.Outside == nil && r.Limit == nil
		if catchAll && r.Action == ActionAllow && toolsOverlap(tool, r.Tool) {
			return r.Name
		}
	}
	return ""
}

// formatList prints a condition value the way it was written in YAML.
func formatList(v any) string {
	items, ok := v.([]any)
	if !ok {
		return fmt.Sprint(v)
	}
	parts := make([]string, len(items))
	for i, item := range items {
		parts[i] = fmt.Sprint(item)
	}
	return "in [" + strings.Join(parts, ", ") + "]"
}

// toolsOverlap reports whether two tool patterns can match the same tool,
// as far as a quick check can tell: they are equal, or one matches the other
// read as a name (payments.* overlaps payments.refund).
func toolsOverlap(a, b string) bool {
	return a == b || matchTool(a, b) || matchTool(b, a)
}

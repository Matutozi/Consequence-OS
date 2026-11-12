package policy

import (
	"errors"
	"strconv"
	"strings"
)

// A condition's arg names a top-level argument, or a dotted path into one,
// for tools that nest their arguments:
//
//	options.environment   the environment field of the options object
//	items.*.amount        the amount of every item of a list (or every member of an object)
//	items.0.amount        the amount of the first item
//
// An argument whose own name holds a dot still matches by that whole name:
// when args has a key equal to arg, the key wins and no path is followed,
// so a rule written before paths existed keeps its meaning.
//
// How the values found are judged depends on the rule; see
// Condition.holds. Deny and ask rules match when any value matches. Allow
// rules need every value to match, and the path to have found them all.

// validPath checks a dotted path: no empty parts, and the first part must
// name an argument rather than be "*".
func validPath(arg string) error {
	if !strings.Contains(arg, ".") {
		return nil
	}
	parts := strings.Split(arg, ".")
	for _, p := range parts {
		if p == "" {
			return errors.New("has an empty part; write it like options.environment or items.*.amount")
		}
	}
	if parts[0] == "*" {
		return errors.New("must start with an argument's name, not *")
	}
	return nil
}

// lookup returns the values arg names in args. With loose, a name at any
// level may differ in letter case. complete is false when a branch of the
// path found nothing: a list item without the field, a missing member, an
// empty list under *, or a value that isn't an object or list where the
// path goes on. A name not in args at all finds nothing, also incomplete.
func lookup(args map[string]any, arg string, loose bool) (vals []any, complete bool) {
	if whole := named(args, arg, loose); len(whole) > 0 || !strings.Contains(arg, ".") {
		return whole, len(whole) > 0
	}
	return walk(args, strings.Split(arg, "."), loose)
}

// named returns the members of obj called name, in any letter case with loose.
func named(obj map[string]any, name string, loose bool) []any {
	var out []any
	if v, ok := obj[name]; ok {
		out = append(out, v)
	}
	if loose {
		for k, v := range obj {
			if k != name && strings.EqualFold(k, name) {
				out = append(out, v)
			}
		}
	}
	return out
}

func walk(node any, path []string, loose bool) (vals []any, complete bool) {
	if len(path) == 0 {
		return []any{node}, true
	}
	part, rest := path[0], path[1:]
	var next []any
	switch n := node.(type) {
	case map[string]any:
		if part == "*" {
			for _, v := range n {
				next = append(next, v)
			}
		} else {
			next = named(n, part, loose)
		}
	case []any:
		if part == "*" {
			next = n
		} else if i, err := strconv.Atoi(part); err == nil && i >= 0 && i < len(n) {
			next = []any{n[i]}
		}
	}
	if len(next) == 0 {
		return nil, false
	}
	complete = true
	for _, child := range next {
		got, ok := walk(child, rest, loose)
		vals = append(vals, got...)
		complete = complete && ok
	}
	return vals, complete
}

// holds reports whether the condition holds for args, judged the way the
// rule needs. loose (deny and ask rules) matches when any value found, by
// names in any letter case, matches: a variant or one item among many
// can't get past it. Otherwise (allow rules) every value found by exact
// names must match, and the path must have found them all: one bad item,
// or an item missing the field, can't ride along with good ones.
func (c Condition) holds(args map[string]any, loose bool) bool {
	vals, complete := lookup(args, c.Arg, loose)
	if loose {
		for _, v := range vals {
			if c.matchValue(v) {
				return true
			}
		}
		return false
	}
	if !complete || len(vals) == 0 {
		return false
	}
	for _, v := range vals {
		if !c.matchValue(v) {
			return false
		}
	}
	return true
}

// limitAmount is what a call adds to a sum limit on arg: the total of the
// values a path with * finds (every item counts), otherwise the largest of
// the values found (several only when a name comes in more than one letter
// case, and then over-counting is the safe way round). negative reports
// whether any value was below zero. ok is false when no value is a number.
func limitAmount(args map[string]any, arg string, loose bool) (amount float64, negative, ok bool) {
	vals, _ := lookup(args, arg, loose)
	sum := strings.Contains(arg, "*") && len(named(args, arg, loose)) == 0
	for _, v := range vals {
		f, isNum := toNumber(v)
		if !isNum {
			continue
		}
		negative = negative || f < 0
		switch {
		case sum:
			amount += f
		case !ok || f > amount:
			amount = f
		}
		ok = true
	}
	return amount, negative, ok
}

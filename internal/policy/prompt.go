package policy

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// MCP prompt arguments are always strings, so a rule like
// { arg: limit, op: gt, value: 1000 } could never match a prompt's limit
// of "5000", and a deny on it never fired. For prompt calls only, each
// string argument is wrapped as promptText: gt, gte, lt and lte read it as
// a number when it is one, and every other operator sees the text as sent,
// so eq "5" still matches "5".
//
// What counts as a number depends on the rule, as names do (see 0.8):
//   - allow rules need a plain decimal, like 5000 or -12.5: anything else
//     doesn't match, and the call falls through;
//   - deny and ask rules also read what a server's parser might accept,
//     so a spelling can't slip past them: spaces around it, a + sign,
//     underscores, an exponent, hex, Inf, and digits from other scripts,
//     as Python's int and float and JavaScript's Number read them.
//
// Tool arguments keep their JSON types: a number sent as text there still
// doesn't match, which fails closed for allow rules.

// promptText is one string argument of a prompt call.
type promptText string

// plainDecimal is the only form allow rules read as a number.
var plainDecimal = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)

// number reads t as a number, strictly for allow rules, loosely for the rest.
func (t promptText) number(loose bool) (float64, bool) {
	s := string(t)
	if !loose {
		if !plainDecimal.MatchString(s) {
			return 0, false
		}
		f, err := strconv.ParseFloat(s, 64)
		return f, err == nil
	}
	s = strings.TrimFunc(asciiDigits(s), unicode.IsSpace)
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, true
	}
	if i, err := strconv.ParseInt(s, 0, 64); err == nil { // 0x10, 0o17, 0b101
		return float64(i), true
	}
	return 0, false
}

// asciiDigits replaces each decimal digit from another script, such as
// "٢" or "５", with its ASCII digit. Such digits come in runs of ten from
// zero to nine, and adjacent runs are whole, so a digit's value is its
// distance from the start of its run, mod 10.
func asciiDigits(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= unicode.MaxASCII || !unicode.Is(unicode.Nd, r) {
			return r
		}
		start := r
		for unicode.Is(unicode.Nd, start-1) {
			start--
		}
		return '0' + (r-start)%10
	}, s)
}

// ordering reports whether op compares sizes.
func ordering(op Op) bool { return op == OpGt || op == OpGte || op == OpLt || op == OpLte }

// promptValue is what condition c compares a prompt argument as: its
// number for an ordering, when it is one, and its text otherwise.
func promptValue(v any, op Op, loose bool) any {
	t, ok := v.(promptText)
	if !ok {
		return v
	}
	if ordering(op) {
		if f, ok := t.number(loose); ok {
			return f
		}
	}
	return string(t)
}

// IsPrompt reports whether name is a prompt fetch, "prompt:<name>".
func IsPrompt(name string) bool { return strings.HasPrefix(name, "prompt:") }

// promptArgs returns a copy of a prompt call's arguments with each string,
// at any depth, wrapped as promptText.
func promptArgs(args map[string]any) map[string]any {
	if args == nil {
		return nil
	}
	return wrapText(args).(map[string]any)
}

func wrapText(v any) any {
	switch x := v.(type) {
	case string:
		return promptText(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, child := range x {
			out[k] = wrapText(child)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, child := range x {
			out[i] = wrapText(child)
		}
		return out
	}
	return v
}

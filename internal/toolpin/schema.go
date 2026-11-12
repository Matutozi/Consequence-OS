package toolpin

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// HTTPServer names an HTTP upstream for its pins: its URL without user
// info, query or fragment, which may hold credentials.
func HTTPServer(upstream string) string {
	u, err := url.Parse(upstream)
	if err != nil {
		return upstream
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}

// StdioServer names a stdio server for its pins: "stdio:" and its command
// line, so servers sharing a state_dir keep their pins apart.
func StdioServer(command []string) string {
	parts := make([]string, len(command))
	for i, c := range command {
		if c == "" || strings.ContainsAny(c, " \t\n\"'\\") {
			c = strconv.Quote(c)
		}
		parts[i] = c
	}
	return "stdio: " + strings.Join(parts, " ")
}

// Has reports whether a rule's arg, a top-level name or a dotted path
// (see internal/policy/paths.go), can name a value under schema. It says
// yes where it can't tell: at a level that combines schemas, or takes
// arguments it doesn't name.
func Has(schema any, arg string) bool {
	s, ok := schema.(map[string]any)
	if !ok {
		return true
	}
	if props, ok := s["properties"].(map[string]any); ok {
		if _, whole := props[arg]; whole {
			return true // a name with a dot in it wins over the path
		}
	}
	return has(s, strings.Split(arg, "."))
}

func has(schema any, path []string) bool {
	s, ok := schema.(map[string]any)
	if !ok || len(path) == 0 || !checkable(s) {
		return true
	}
	part, rest := path[0], path[1:]
	if items, ok := s["items"]; ok && typed(s, "array") {
		if _, err := strconv.Atoi(part); err == nil || part == "*" {
			return has(items, rest)
		}
	}
	props, hasProps := s["properties"].(map[string]any)
	if !hasProps && !typed(s, "object") {
		return false
	}
	if extra, set := s["additionalProperties"]; set && extra != false {
		return true
	}
	if part == "*" {
		for _, sub := range props {
			if has(sub, rest) {
				return true
			}
		}
		return false
	}
	sub, ok := props[part]
	return ok && has(sub, rest)
}

// checkable reports whether a level's names can be read from its
// properties alone.
func checkable(s map[string]any) bool {
	for _, k := range combinators {
		if _, ok := s[k]; ok {
			return false
		}
	}
	return true
}

// Paths lists the dotted path of every value schema names, sorted, with *
// for list items: options, options.environment, items, items.*.amount.
func Paths(schema any) []string {
	var out []string
	var walk func(schema any, prefix string, depth int)
	walk = func(schema any, prefix string, depth int) {
		s, ok := schema.(map[string]any)
		if !ok || depth > 32 {
			return
		}
		if items, ok := s["items"]; ok && prefix != "" {
			walk(items, prefix+".*", depth+1)
		}
		props, _ := s["properties"].(map[string]any)
		for name, sub := range props {
			p := join(prefix, name)
			out = append(out, p)
			walk(sub, p, depth+1)
		}
	}
	walk(schema, "", 0)
	sort.Strings(out)
	return out
}

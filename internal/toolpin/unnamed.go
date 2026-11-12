package toolpin

import (
	"sort"
	"strconv"
)

// A call to a pinned tool may only send the arguments its accepted input
// schema names. Otherwise an argument the schema never mentioned, such as
// a delete_all the server quietly honours, or "Environment" beside the
// schema's "environment", goes past rules written for the schema's names.
//
// The check follows plain object schemas: at each level where the schema
// says the value is an object (type "object", or properties), every key
// must be one of its properties, unless additionalProperties is true or a
// schema. Named properties are checked in turn, and so are list items
// under items. MCP's own form for a tool with no arguments,
// {"type": "object"}, names none, so any argument is refused.
//
// A level that combines schemas ($ref, allOf, anyOf, oneOf, if,
// patternProperties and the like) isn't checked, since which names it
// allows depends on more than its properties. Neither is anything below
// it. That is the permissive reading, kept narrow: it covers only levels
// this check can't read, and every other check still applies.

// combinators are the keywords that make a level's allowed names depend
// on more than its properties.
var combinators = []string{
	"$ref", "$dynamicRef", "allOf", "anyOf", "oneOf", "not", "if", "then", "else",
	"dependentSchemas", "patternProperties", "unevaluatedProperties", "propertyNames",
}

// unnamed returns the dotted path of the first argument in value that
// schema doesn't name, in sorted key order, or "" when there is none.
func unnamed(schema, value any, path string) string {
	s, ok := schema.(map[string]any)
	if !ok {
		return ""
	}
	for _, k := range combinators {
		if _, ok := s[k]; ok {
			return ""
		}
	}
	switch v := value.(type) {
	case map[string]any:
		props, hasProps := s["properties"].(map[string]any)
		if !hasProps && !typed(s, "object") {
			return ""
		}
		extra, set := s["additionalProperties"]
		open := set && extra != false // true, or a schema the extra values must fit
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sub, named := props[k]
			if !named {
				if open {
					continue
				}
				return join(path, k)
			}
			if p := unnamed(sub, v[k], join(path, k)); p != "" {
				return p
			}
		}
	case []any:
		items, ok := s["items"]
		if !ok {
			return ""
		}
		for i, item := range v {
			if p := unnamed(items, item, join(path, strconv.Itoa(i))); p != "" {
				return p
			}
		}
	}
	return ""
}

// typed reports whether schema's type is want, or a list holding it.
func typed(schema map[string]any, want string) bool {
	switch t := schema["type"].(type) {
	case string:
		return t == want
	case []any:
		for _, x := range t {
			if x == want {
				return true
			}
		}
	}
	return false
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

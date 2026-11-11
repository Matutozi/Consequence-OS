package policy

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Conditions is the "when" part of a rule; every condition must hold.
// In YAML it can be written as one condition or as a list:
//
//	when: { arg: amount, op: lte, value: 50 }
//
//	when:
//	  - { arg: amount, op: lte, value: 50 }
//	  - { arg: currency, op: in, value: [USD, EUR], fold: true }
type Conditions []Condition

// UnmarshalYAML lets yaml.v3 decode either form. Defining this method is
// how a Go type customises its own decoding (like a pydantic validator).
func (c *Conditions) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.MappingNode:
		cond, err := decodeCondition(node)
		if err != nil {
			return err
		}
		*c = Conditions{cond}
	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			return fmt.Errorf("line %d: when list is empty; remove when to match every call", node.Line)
		}
		list := make(Conditions, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind != yaml.MappingNode {
				return fmt.Errorf("line %d: each when item must be a condition like { arg: amount, op: lte, value: 50 }", item.Line)
			}
			cond, err := decodeCondition(item)
			if err != nil {
				return err
			}
			list = append(list, cond)
		}
		*c = list
	default:
		return fmt.Errorf("line %d: when must be a condition or a list of conditions", node.Line)
	}
	return nil
}

// decodeCondition decodes one mapping, rejecting unknown keys. node.Decode
// does not inherit the config loader's strict mode, so we check keys here.
func decodeCondition(node *yaml.Node) (Condition, error) {
	// A mapping node's Content alternates key, value, key, value.
	for i := 0; i < len(node.Content); i += 2 {
		switch key := node.Content[i]; key.Value {
		case "arg", "op", "value", "fold":
		default:
			return Condition{}, fmt.Errorf("line %d: unknown condition field %q (want arg, op, value, fold)", key.Line, key.Value)
		}
	}
	var cond Condition
	if err := node.Decode(&cond); err != nil {
		return Condition{}, err
	}
	return cond, nil
}

func (c Conditions) validate() error {
	for i, cond := range c {
		if err := cond.validate(); err != nil {
			if len(c) > 1 {
				return fmt.Errorf("when item %d: %w", i+1, err)
			}
			return err
		}
	}
	return nil
}

// matches reports whether every condition holds. An empty list always matches.
func (c Conditions) matches(args map[string]any) bool {
	for _, cond := range c {
		if !cond.matches(args) {
			return false
		}
	}
	return true
}

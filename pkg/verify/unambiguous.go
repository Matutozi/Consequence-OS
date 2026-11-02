package verify

import (
	"encoding/json"
	"errors"
	"strings"
)

// ErrCaseVariantKeys is returned when an object has two keys that differ
// only in letter case, like "amount" and "Amount".
var ErrCaseVariantKeys = errors.New("verify: keys that differ only in letter case")

// CheckUnambiguous rejects JSON that different parsers could read
// differently: invalid JSON, duplicate keys, and keys that differ only in
// case. Many decoders (Go's encoding/json among them) treat "amount" and
// "Amount" as the same field and keep the last, so a policy could check
// amount=10 while the tool sees 5000. The proxy and receivers both call this.
func CheckUnambiguous(body []byte) error {
	if _, err := Canonicalize(body); err != nil {
		return err
	}
	var v any
	_ = json.Unmarshal(body, &v) // valid: Canonicalize just parsed it
	if hasCaseVariantKeys(v) {
		return ErrCaseVariantKeys
	}
	return nil
}

func hasCaseVariantKeys(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		seen := make(map[string]bool, len(x))
		for k, child := range x {
			// Upper then lower folds special letters too (e.g. "ſ" and "s").
			folded := strings.ToLower(strings.ToUpper(k))
			if seen[folded] || hasCaseVariantKeys(child) {
				return true
			}
			seen[folded] = true
		}
	case []any:
		for _, child := range x {
			if hasCaseVariantKeys(child) {
				return true
			}
		}
	}
	return false
}

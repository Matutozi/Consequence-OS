// Package verify is the public library for services that receive actions
// from ConsequenceOS. Everything here must behave identically on both sides,
// starting with how tool arguments are hashed.
package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// maxDepth bounds nesting so a hostile document can't recurse forever.
const maxDepth = 100

// ErrDuplicateKey is returned when an object repeats a key. Different JSON
// parsers keep different copies of a duplicate, so we refuse them outright.
var ErrDuplicateKey = errors.New("verify: duplicate object key")

// Canonicalize returns the RFC 8785 (JSON Canonicalization Scheme) form of a
// JSON document: object keys sorted by UTF-16 code units, no whitespace,
// minimal string escaping and ECMAScript number formatting. The same data
// always produces the same bytes, which is what makes hashing it meaningful.
func Canonicalize(data []byte) ([]byte, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("verify: JSON is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // keep numbers as text so we control how they're formatted

	var out bytes.Buffer
	if err := writeValue(dec, &out, 0); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("verify: unexpected data after the JSON value")
	}
	return out.Bytes(), nil
}

// ParamsHash returns "sha256:<hex>" of the canonical form of a tool call's
// arguments. Absent or null arguments hash the same as an empty object.
func ParamsHash(arguments []byte) (string, error) {
	trimmed := bytes.TrimSpace(arguments)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		trimmed = []byte("{}")
	}
	canonical, err := Canonicalize(trimmed)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func writeValue(dec *json.Decoder, out *bytes.Buffer, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("verify: JSON nested deeper than %d levels", maxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("verify: invalid JSON: %w", err)
	}
	// A type switch picks a branch by the dynamic type held in an interface.
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			return writeObject(dec, out, depth)
		case '[':
			return writeArray(dec, out, depth)
		}
		return fmt.Errorf("verify: invalid JSON: unexpected %q", v)
	case string:
		writeString(out, v)
	case json.Number:
		s, err := formatNumber(v)
		if err != nil {
			return err
		}
		out.WriteString(s)
	case bool:
		out.WriteString(strconv.FormatBool(v))
	case nil:
		out.WriteString("null")
	}
	return nil
}

type member struct {
	key   string
	value []byte
}

func writeObject(dec *json.Decoder, out *bytes.Buffer, depth int) error {
	var members []member
	seen := make(map[string]bool)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("verify: invalid JSON: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("verify: invalid JSON: object key is not a string")
		}
		if seen[key] {
			return fmt.Errorf("%w %q", ErrDuplicateKey, key)
		}
		seen[key] = true

		var value bytes.Buffer
		if err := writeValue(dec, &value, depth+1); err != nil {
			return err
		}
		members = append(members, member{key: key, value: value.Bytes()})
	}
	if _, err := dec.Token(); err != nil { // the closing '}'
		return fmt.Errorf("verify: invalid JSON: %w", err)
	}

	sort.Slice(members, func(i, j int) bool { return lessUTF16(members[i].key, members[j].key) })
	out.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			out.WriteByte(',')
		}
		writeString(out, m.key)
		out.WriteByte(':')
		out.Write(m.value)
	}
	out.WriteByte('}')
	return nil
}

func writeArray(dec *json.Decoder, out *bytes.Buffer, depth int) error {
	out.WriteByte('[')
	for i := 0; dec.More(); i++ {
		if i > 0 {
			out.WriteByte(',')
		}
		if err := writeValue(dec, out, depth+1); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // the closing ']'
		return fmt.Errorf("verify: invalid JSON: %w", err)
	}
	out.WriteByte(']')
	return nil
}

// writeString escapes only what JSON requires, as RFC 8785 specifies.
func writeString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for _, r := range s { // ranging over a string yields runes (code points), not bytes
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

// formatNumber renders a number the way JavaScript's Number.toString does,
// which is what RFC 8785 requires. Numbers are treated as IEEE 754 doubles.
func formatNumber(n json.Number) (string, error) {
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil {
		return "", fmt.Errorf("verify: number %s is out of range", n)
	}
	if f == 0 {
		return "0", nil // also turns -0 into 0
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}

	// Go's shortest round-trip formatting gives the same digits JavaScript
	// picks; only the layout differs. "3.3333e+08" -> digits "33333", n = 9.
	mantissa, exp, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	e, _ := strconv.Atoi(exp)
	k, point := len(digits), e+1 // point: where the decimal point sits

	var s string
	switch {
	case k <= point && point <= 21: // integer: 1500, 100000000000000000000
		s = digits + strings.Repeat("0", point-k)
	case 0 < point && point <= 21: // decimal: 4.5, 333333333.3333333
		s = digits[:point] + "." + digits[point:]
	case -6 < point && point <= 0: // small decimal: 0.002, 0.000001
		s = "0." + strings.Repeat("0", -point) + digits
	default: // exponent: 1e+21, 1.5e-7
		s = digits[:1]
		if k > 1 {
			s += "." + digits[1:]
		}
		if point-1 >= 0 {
			s += "e+" + strconv.Itoa(point-1)
		} else {
			s += "e-" + strconv.Itoa(1-point)
		}
	}
	return sign + s, nil
}

// lessUTF16 orders keys by UTF-16 code units, as RFC 8785 requires. This
// differs from Go's byte order for characters outside the Basic Multilingual Plane.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

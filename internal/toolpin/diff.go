package toolpin

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Diff shows how one definition differs from another, line by line, as
// indented JSON: unchanged lines start with two spaces, removed ones with
// "- " and added ones with "+ ". Definitions are canonical JSON, so keys
// come in the same order in both, and the lines line up.
func Diff(old, new json.RawMessage) string {
	a, b := lines(old), lines(new)
	// lcs[i][j] is the length of the longest common subsequence of a[i:]
	// and b[j:]. Definitions run to hundreds of lines, so the table is small.
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out strings.Builder
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			out.WriteString("  " + a[i] + "\n")
			i, j = i+1, j+1
		case i < len(a) && (j == len(b) || lcs[i+1][j] >= lcs[i][j+1]):
			out.WriteString("- " + a[i] + "\n") // what was removed comes first
			i++
		default:
			out.WriteString("+ " + b[j] + "\n")
			j++
		}
	}
	return out.String()
}

func lines(def json.RawMessage) []string {
	var buf bytes.Buffer
	if json.Indent(&buf, def, "", "  ") != nil {
		return strings.Split(string(def), "\n")
	}
	return strings.Split(buf.String(), "\n")
}

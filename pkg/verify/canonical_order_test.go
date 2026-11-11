package verify

import (
	"math/rand/v2"
	"testing"
	"unicode/utf16"
)

// lessUTF16Reference is the plain definition: encode both, then compare.
func lessUTF16Reference(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func TestLessUTF16MatchesTheDefinition(t *testing.T) {
	// Characters picked to hit the cases that differ from byte order:
	// ASCII, the top of the BMP above the surrogates, and astral planes.
	alphabet := []rune{'a', 'b', 'z', 0x7f, 0xe9, 0x20ac, 0xd7ff, 0xe000, 0xfb33, 0xffee, 0x10000, 0x1d11e, 0x1f600, 0x1f601, 0x10ffff}
	r := rand.New(rand.NewPCG(1, 2))
	word := func() string {
		n := r.IntN(4)
		out := make([]rune, n)
		for i := range out {
			out[i] = alphabet[r.IntN(len(alphabet))]
		}
		return string(out)
	}
	for range 200_000 {
		a, b := word(), word()
		if got, want := lessUTF16(a, b), lessUTF16Reference(a, b); got != want {
			t.Fatalf("lessUTF16(%q, %q) = %v, want %v", a, b, got, want)
		}
	}
	// The case RFC 8785 calls out: U+FB33 sorts after U+1F600 in UTF-16.
	if !lessUTF16("\U0001F600", "דּ") {
		t.Error("an astral character should sort before U+FB33")
	}
}

func TestLessUTF16DoesNotAllocate(t *testing.T) {
	if n := testing.AllocsPerRun(100, func() { lessUTF16("params_hash\U0001F600", "params_hashדּ") }); n != 0 {
		t.Errorf("lessUTF16 allocates %v times per call", n)
	}
}

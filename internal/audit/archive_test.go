package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// chainOf makes n chained entries, starting after prev ("" for the start).
func chainFrom(t *testing.T, prev string, from int64, n int) []Entry {
	t.Helper()
	var out []Entry
	for i := 0; i < n; i++ {
		e, err := Chain(prev, Entry{ID: fmt.Sprintf("aud_%d", from), Time: time.Date(2026, 1, 1, 0, 0, int(from), 0, time.UTC),
			AgentID: "a", Tool: "x", Outcome: OutcomeForwarded})
		if err != nil {
			t.Fatal(err)
		}
		e.Seq = from
		out = append(out, e)
		prev, from = e.Hash, from+1
	}
	return out
}

// headFor stands in for signed heads: a head is "seq hash", and
// checking it reads them back. "forged" fails.
func headFor(e Entry) json.RawMessage {
	b, _ := json.Marshal(fmt.Sprintf("%d %s", e.Seq, e.Hash))
	return b
}

func checkHeadFor(signed []byte) (int64, string, error) {
	var s string
	if err := json.Unmarshal(signed, &s); err != nil || s == "forged" {
		return 0, "", errors.New("bad signature")
	}
	var seq int64
	var hash string
	_, err := fmt.Sscanf(s, "%d %s", &seq, &hash)
	return seq, hash, err
}

func archiveOf(t *testing.T, after *Anchor, entries []Entry) []byte {
	t.Helper()
	last := entries[len(entries)-1]
	h := ArchiveHeader{After: after, Through: Anchor{Seq: last.Seq, Hash: last.Hash, Head: headFor(last), At: time.Now()}, Entries: int64(len(entries))}
	var buf bytes.Buffer
	err := WriteArchive(&buf, h, func(yield func(Entry) error) error {
		for _, e := range entries {
			if err := yield(e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestVerifyArchive(t *testing.T) {
	first := chainFrom(t, "", 1, 3)
	second := chainFrom(t, first[2].Hash, 4, 3)
	after := &Anchor{Seq: first[2].Seq, Hash: first[2].Hash, Head: headFor(first[2])}

	for name, file := range map[string][]byte{"first": archiveOf(t, nil, first), "second": archiveOf(t, after, second)} {
		rep, err := VerifyArchive(bytes.NewReader(file), checkHeadFor)
		if err != nil || !rep.Intact || rep.Through != AnchorChecked || rep.Checked != 3 {
			t.Errorf("%s archive: %+v, %v", name, rep, err)
		}
		if rep, _ := VerifyArchive(bytes.NewReader(file), nil); !rep.Intact || rep.Through != AnchorNotChecked {
			t.Errorf("%s archive without keys: %+v", name, rep)
		}
	}
	if rep, _ := VerifyArchive(bytes.NewReader(archiveOf(t, after, second)), checkHeadFor); rep.Anchor != AnchorChecked {
		t.Errorf("the second archive's start: %q, want its head checked", rep.Anchor)
	}

	good := archiveOf(t, nil, first)
	lines := strings.SplitAfter(string(good), "\n")
	edit := func(f func([]string) []string) []byte {
		return []byte(strings.Join(f(append([]string(nil), lines...)), ""))
	}
	tests := map[string]struct {
		file []byte
		want string
	}{
		"an entry changed": {edit(func(l []string) []string {
			l[2] = strings.Replace(l[2], `"tool":"x"`, `"tool":"y"`, 1)
			return l
		}), "contents don't match"},
		"an entry removed from the middle": {edit(func(l []string) []string { return append(l[:2], l[3:]...) }), "does not link"},
		"the last entry removed":           {edit(func(l []string) []string { return l[:3] }), "holds 2 entries, but its header says 3"},
		"the last entry removed, header edited": {edit(func(l []string) []string {
			l[0] = strings.Replace(l[0], `"entries":3`, `"entries":2`, 1)
			return l[:3]
		}), "the header says it ends at 3"},
		"a forged head": {edit(func(l []string) []string {
			l[0] = strings.Replace(l[0], string(headFor(first[2])), `"forged"`, 1)
			return l
		}), "the signed head at the end doesn't check out"},
		"a head for another entry": {edit(func(l []string) []string {
			l[0] = strings.Replace(l[0], string(headFor(first[2])), string(headFor(first[1])), 1)
			return l
		}), "names entry 2"},
		"the wrong start": {archiveOf(t, &Anchor{Seq: 9, Hash: "sha256:other", Head: headFor(Entry{Seq: 9, Hash: "sha256:other"})}, second), "does not link"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rep, err := VerifyArchive(bytes.NewReader(tt.file), checkHeadFor)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Intact || !strings.Contains(rep.Problem, tt.want) {
				t.Errorf("report %+v, want a problem with %q", rep, tt.want)
			}
		})
	}
	for _, bad := range []string{"", `{"type":"something-else"}` + "\n", `{"type":"` + ArchiveType + `","extra":1}` + "\n"} {
		if _, err := VerifyArchive(strings.NewReader(bad), checkHeadFor); err == nil {
			t.Errorf("%q read as an archive", bad)
		}
	}
}

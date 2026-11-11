package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/policy"
)

var t0 = time.Date(2026, 11, 2, 10, 0, 0, 123456789, time.UTC)

// chainOf builds a correctly linked log of n entries.
func chainOf(t *testing.T, n int) []Entry {
	t.Helper()
	var out []Entry
	prev := ""
	for i := 0; i < n; i++ {
		e, err := Chain(prev, Entry{
			ID: "aud_" + string(rune('a'+i)), Time: t0.Add(time.Duration(i) * time.Second),
			AgentID: "bot", OwnerID: "acme", Tool: "payments.refund", Decision: policy.ActionAllow,
			Outcome: OutcomeForwarded, Summary: "payments.refund with amount",
		})
		if err != nil {
			t.Fatal(err)
		}
		e.Seq = int64(i + 1)
		out = append(out, e)
		prev = e.Hash
	}
	return out
}

func verifyAll(entries []Entry) ChainReport {
	var v ChainVerifier
	for _, e := range entries {
		if !v.Add(e) {
			break
		}
	}
	return v.Report()
}

func TestChainHash(t *testing.T) {
	e := Entry{ID: "aud_1", Time: t0, Tool: "x", Outcome: OutcomeForwarded}
	a, _ := ChainHash("", e)
	b, _ := ChainHash("", e)
	if a != b || !strings.HasPrefix(a, "sha256:") || len(a) != len("sha256:")+64 {
		t.Fatalf("hash not stable or badly formed: %q %q", a, b)
	}
	// Nanoseconds beyond the stored precision don't change the hash.
	e2 := e
	e2.Time = t0.Truncate(Precision)
	if c, _ := ChainHash("", e2); c != a {
		t.Error("hash depends on sub-microsecond time")
	}
	// Every field and the link are covered.
	changes := map[string]func(*Entry){
		"tool":    func(e *Entry) { e.Tool = "y" },
		"summary": func(e *Entry) { e.Summary = "s" },
		"outcome": func(e *Entry) { e.Outcome = OutcomeBlocked },
		"time":    func(e *Entry) { e.Time = e.Time.Add(time.Microsecond) },
		"receipt": func(e *Entry) { e.ReceiptID = "rcpt_x" },
	}
	for name, change := range changes {
		c := e
		change(&c)
		if h, _ := ChainHash("", c); h == a {
			t.Errorf("changing %s didn't change the hash", name)
		}
	}
	if h, _ := ChainHash("sha256:other", e); h == a {
		t.Error("the previous hash isn't covered")
	}
}

func TestVerifyChain(t *testing.T) {
	tests := []struct {
		name       string
		tamper     func([]Entry) []Entry
		intact     bool
		brokenAt   string
		wantReason string
	}{
		{"untouched", func(e []Entry) []Entry { return e }, true, "", ""},
		{"edited field", func(e []Entry) []Entry { e[2].Summary = "nothing to see"; return e }, false, "aud_c", "changed"},
		{"edited hash too", func(e []Entry) []Entry {
			e[2].Summary = "nothing to see"
			e[2].Hash, _ = ChainHash(e[2].PrevHash, e[2])
			return e
		}, false, "aud_d", "does not link"},
		{"deleted entry", func(e []Entry) []Entry { return append(e[:1], e[2:]...) }, false, "aud_c", "does not link"},
		{"swapped order", func(e []Entry) []Entry { e[1], e[2] = e[2], e[1]; return e }, false, "aud_c", "does not link"},
		{"blanked hash", func(e []Entry) []Entry { e[3].Hash = ""; return e }, false, "aud_d", "no hash"},
		{"last entry removed", func(e []Entry) []Entry { return e[:4] }, true, "", ""}, // only a signed head catches this
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := verifyAll(tt.tamper(chainOf(t, 5)))
			if r.Intact != tt.intact || r.BrokenAt != tt.brokenAt || !strings.Contains(r.Problem, tt.wantReason) {
				t.Errorf("report = %+v", r)
			}
		})
	}
}

func TestUnhashedEntriesBeforeTheChain(t *testing.T) {
	old := []Entry{{ID: "aud_old1", Seq: 1}, {ID: "aud_old2", Seq: 2}} // written before the migration
	r := verifyAll(append(old, chainOf(t, 3)...))
	if !r.Intact || r.Unhashed != 2 || r.Checked != 3 {
		t.Errorf("report = %+v", r)
	}
}

type walker []Entry

func (w walker) ForEachAudit(_ context.Context, fn func(Entry) error) error {
	for _, e := range w {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func TestVerifyChainWalksAndReportsHead(t *testing.T) {
	entries := chainOf(t, 3)
	r, err := VerifyChain(context.Background(), walker(entries))
	if err != nil || !r.Intact || r.Checked != 3 || r.HeadSeq != 3 || r.HeadHash != entries[2].Hash {
		t.Errorf("report = %+v, err = %v", r, err)
	}
}

func TestSavedHead(t *testing.T) {
	entries := chainOf(t, 5)
	tests := []struct {
		name    string
		log     []Entry
		seq     int64
		hash    string
		intact  bool
		problem string
	}{
		{"head still there", entries, 4, entries[3].Hash, true, ""},
		{"later entries are fine", entries, 2, entries[1].Hash, true, ""},
		{"end of the log removed", entries[:3], 4, entries[3].Hash, false, "missing"},
		{"head entry rewritten", entries, 4, "sha256:" + strings.Repeat("0", 64), false, "saved head"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v ChainVerifier
			v.ExpectHead(tt.seq, tt.hash)
			r, err := VerifyChainWith(context.Background(), walker(tt.log), &v)
			if err != nil || r.Intact != tt.intact || !strings.Contains(r.Problem, tt.problem) {
				t.Errorf("report = %+v, err = %v", r, err)
			}
		})
	}
}

// An entry written before scores existed must hash exactly as it did then.
// The hash below was computed by the code before the score field was added.
func TestEntriesFromBeforeScoresStillVerify(t *testing.T) {
	e := Entry{ID: "aud_golden", Time: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC), AgentID: "support-bot", OwnerID: "acme",
		Tool: "payments.refund", ParamsHash: "sha256:p", Summary: "payments.refund with amount", Level: "irreversible",
		Decision: "ask", Rule: "big-refunds", Outcome: OutcomeHeld, ApprovalID: "apr_1"}
	got, err := ChainHash("sha256:prev", e)
	if err != nil {
		t.Fatal(err)
	}
	if want := "sha256:55e350256d81d729d570c08d4b84a601b3faf8dc0f08ef47f33db76890f76d23"; got != want {
		t.Errorf("hash = %s, want %s", got, want)
	}

	// A score is covered by the hash, so changing it breaks the chain.
	e.Score = 80
	scored, _ := ChainHash("sha256:prev", e)
	e.Score = 20
	lowered, _ := ChainHash("sha256:prev", e)
	if scored == got || scored == lowered {
		t.Error("the score is not covered by the hash")
	}
}

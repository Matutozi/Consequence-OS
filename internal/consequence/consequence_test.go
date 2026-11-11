package consequence

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/matutozi/consequence-os/pkg/verify"
)

func TestStaticReproducesLevels(t *testing.T) {
	s := NewStatic(map[string]Reversibility{
		"notes.read": Read, "notes.update": Reversible, "payments.refund": None,
		"resource:file:///secrets/key": None,
	})
	tests := []struct {
		tool   string
		score  int
		rev    Reversibility
		reason string
	}{
		{"notes.read", 0, Read, "notes.read is listed as a read in the tools map."},
		{"notes.update", 40, Reversible, "notes.update is listed as reversible in the tools map."},
		{"payments.refund", 80, None, "payments.refund is listed as irreversible in the tools map."},
		{"rockets.launch", 80, None, "rockets.launch isn't in the tools map, so it counts as irreversible."},
		{"resource:file:///notes/a", 0, Read, "Resources and prompts that aren't in the tools map count as reads."},
		{"prompt:summarize", 0, Read, "Resources and prompts that aren't in the tools map count as reads."},
		{"resource:file:///secrets/key", 80, None, "resource:file:///secrets/key is listed as irreversible in the tools map."},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			a, err := s.Assess(context.Background(), tt.tool, nil)
			if err != nil {
				t.Fatal(err)
			}
			if a.Score != tt.score || a.Reversibility != tt.rev || a.Source != SourceConfig {
				t.Errorf("got score %d, %s, source %s; want %d, %s, config", a.Score, a.Reversibility, a.Source, tt.score, tt.rev)
			}
			if len(a.Reasons) != 1 || a.Reasons[0] != tt.reason {
				t.Errorf("reasons = %q, want %q", a.Reasons, tt.reason)
			}
			if err := a.Validate(); err != nil {
				t.Errorf("Static made an invalid assessment: %v", err)
			}
		})
	}
}

func TestStaticCopiesItsInput(t *testing.T) {
	tools := map[string]Reversibility{"x": Read}
	s := NewStatic(tools)
	tools["x"] = None
	if a, _ := s.Assess(context.Background(), "x", nil); a.Reversibility != Read {
		t.Error("a later change to the caller's map changed the resolver")
	}
}

// fixed is a resolver that always gives the same answer.
type fixed struct {
	a   Assessment
	err error
}

func (f fixed) Assess(context.Context, string, map[string]any) (Assessment, error) { return f.a, f.err }

func TestMaxKeepsTheWorstView(t *testing.T) {
	config := fixed{a: Assessment{Score: 40, Reversibility: None, Source: SourceConfig,
		Reasons: []string{"listed as irreversible"}, DataClasses: []string{"payment"}}}
	mapped := fixed{a: Assessment{Score: 90, Reversibility: Reversible, BlastRadius: 12, Source: SourceMap,
		MapHash: "sha256:abc", Reasons: []string{"12 services depend on it"}, DataClasses: []string{"personal", "payment"},
		Owners: []string{"@billing"}, Targets: []string{"path:internal/billing/"}}}

	got, err := Max{config, mapped}.Assess(context.Background(), "x", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := Assessment{Score: 90, Reversibility: None, BlastRadius: 12, Source: SourceMap, MapHash: "sha256:abc",
		DataClasses: []string{"payment", "personal"}, Owners: []string{"@billing"}, Targets: []string{"path:internal/billing/"},
		Reasons: []string{"listed as irreversible", "12 services depend on it"}}
	if !equal(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}

	// A lower score from the map can't lower the config's.
	low := fixed{a: Assessment{Score: 5, Reversibility: Read, Source: SourceMap, MapHash: "sha256:abc"}}
	got, _ = Max{config, low}.Assess(context.Background(), "x", nil)
	if got.Score != 40 || got.Reversibility != None || got.Source != SourceConfig || got.MapHash != "" {
		t.Errorf("a lower map score changed the result: %+v", got)
	}
}

func TestMaxFailsWhenAnyResolverFails(t *testing.T) {
	boom := errors.New("map unavailable")
	_, err := Max{fixed{a: Assessment{Source: SourceConfig, Reversibility: Read}}, fixed{err: boom}}.Assess(context.Background(), "x", nil)
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the resolver's error", err)
	}
	if _, err := (Max{}).Assess(context.Background(), "x", nil); err == nil {
		t.Error("an empty Max should fail, not call everything harmless")
	}
}

func TestValidate(t *testing.T) {
	ok := Assessment{Score: 50, Reversibility: Reversible, Source: SourceConfig}
	tests := []struct {
		name   string
		change func(*Assessment)
		want   string
	}{
		{"score too high", func(a *Assessment) { a.Score = 101 }, "outside"},
		{"negative score", func(a *Assessment) { a.Score = -1 }, "outside"},
		{"unknown reversibility", func(a *Assessment) { a.Reversibility = "irreversible" }, "reversibility"},
		{"negative blast radius", func(a *Assessment) { a.BlastRadius = -1 }, "blast radius"},
		{"no source", func(a *Assessment) { a.Source = "" }, "source"},
		{"map without hash", func(a *Assessment) { a.Source = SourceMap }, "hash"},
		{"config with hash", func(a *Assessment) { a.MapHash = "sha256:x" }, "no map hash"},
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := ok
			tt.change(&a)
			if err := a.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// The receipt v1 draft uses the same words, so assessments go into
// receipts unchanged.
func TestValuesMatchReceipts(t *testing.T) {
	pairs := map[string]string{
		string(Read): verify.ReversibilityRead, string(Reversible): verify.ReversibilityReversible,
		string(Compensable): verify.ReversibilityCompensable, string(None): verify.ReversibilityNone,
		SourceConfig: verify.SourceConfig, SourceMap: verify.SourceMap,
	}
	for ours, theirs := range pairs {
		if ours != theirs {
			t.Errorf("%q here is %q in pkg/verify", ours, theirs)
		}
	}
	if MaxScore != verify.MaxScore {
		t.Errorf("MaxScore %d, pkg/verify has %d", MaxScore, verify.MaxScore)
	}
}

func equal(a, b Assessment) bool {
	return a.Score == b.Score && a.Reversibility == b.Reversibility && a.BlastRadius == b.BlastRadius &&
		a.Source == b.Source && a.MapHash == b.MapHash && slices.Equal(a.DataClasses, b.DataClasses) &&
		slices.Equal(a.Owners, b.Owners) && slices.Equal(a.Targets, b.Targets) && slices.Equal(a.Reasons, b.Reasons)
}

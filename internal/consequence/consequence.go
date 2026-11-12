// Package consequence says what a call would affect and how badly. It knows
// nothing about policy, HTTP or storage. A Resolver produces an Assessment,
// and the policy engine matches rules against it.
//
// Phase 1 has one resolver, Static, built from the tools map in the config.
// A computed map of a whole system plugs in later as another Resolver,
// combined with Static by Max so it can never score a call lower.
package consequence

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Reversibility is how hard a call's effects are to undo.
type Reversibility string

// The values match the receipt v1 draft (pkg/verify), so an assessment can
// go into a receipt unchanged.
const (
	Read        Reversibility = "read"        // changes nothing
	Reversible  Reversibility = "reversible"  // can be undone
	Compensable Reversibility = "compensable" // can't be undone, but a known action makes up for it
	None        Reversibility = "none"        // can't be undone
)

// severity orders reversibility from harmless to worst.
var severity = map[Reversibility]int{Read: 0, Reversible: 1, Compensable: 2, None: 3}

// Valid reports whether r is one of the known values.
func (r Reversibility) Valid() bool {
	_, ok := severity[r]
	return ok
}

// Where an assessment came from.
const (
	SourceConfig = "config" // the tools map in consequence.yaml
	SourceMap    = "map"    // a consequence map of the system (phase 2)
)

// MaxScore is the worst score. Scores are integers so they fit receipts,
// whose content rules allow no floats.
const MaxScore = 100

// Default scores for each level in the tools map. With the default
// threshold of 20, they give the same defaults as before scores existed:
// reads are allowed and everything else asks.
const (
	DefaultReadScore         = 0
	DefaultReversibleScore   = 40
	DefaultIrreversibleScore = 80
)

// Assessment is what one call would affect, and how badly.
type Assessment struct {
	Score         int           // 0 (harmless) to 100 (worst)
	Reversibility Reversibility // how hard it is to undo
	BlastRadius   int           // how many things depend on the target; 0 when unknown
	DataClasses   []string      // e.g. "payment", "personal", "auth"
	Owners        []string      // e.g. from CODEOWNERS
	Targets       []string      // what the call acts on, e.g. "path:internal/billing/"
	Reasons       []string      // one plain sentence per thing that raised the score
	Source        string        // SourceConfig or SourceMap
	MapHash       string        // which map answered, when Source is SourceMap
}

// IsZero reports whether a is unset. Every resolver sets Source, so an
// assessment without one was never made.
func (a Assessment) IsZero() bool { return a.Source == "" }

// Validate checks that a is complete and in range. The proxy refuses to
// decide on an assessment that fails, rather than guess.
func (a Assessment) Validate() error {
	switch {
	case a.Score < 0 || a.Score > MaxScore:
		return fmt.Errorf("consequence: score %d is outside 0 to %d", a.Score, MaxScore)
	case !a.Reversibility.Valid():
		return fmt.Errorf("consequence: unknown reversibility %q", a.Reversibility)
	case a.BlastRadius < 0:
		return errors.New("consequence: blast radius can't be negative")
	case a.Source != SourceConfig && a.Source != SourceMap:
		return fmt.Errorf("consequence: unknown source %q", a.Source)
	case a.Source == SourceMap && !strings.HasPrefix(a.MapHash, "sha256:"):
		return errors.New("consequence: an assessment from a map needs the map's sha256: hash")
	case a.Source == SourceConfig && a.MapHash != "":
		return errors.New("consequence: an assessment from the config has no map hash")
	}
	return nil
}

// Resolver assesses a call. An error means it couldn't, and the caller
// must not forward the call.
type Resolver interface {
	Assess(ctx context.Context, tool string, args map[string]any) (Assessment, error)
}

// Resource reads, prompt fetches and requests the server makes of the
// client are assessed, and go past the policy, under these names:
// "resource:" plus the URI, "prompt:" plus the prompt's name, and
// "server:" plus what the server asks for (server:elicitation,
// server:sampling). MCP tool names can't contain ":", so they can't
// collide.
const (
	ResourcePrefix = "resource:"
	PromptPrefix   = "prompt:"
	ServerPrefix   = "server:"
)

// IsRead reports whether name is anything but a tool call: a resource
// read, a prompt fetch, or a request from the server. None of them counts
// as irreversible unless the tools map says so.
func IsRead(name string) bool {
	return strings.HasPrefix(name, ResourcePrefix) || strings.HasPrefix(name, PromptPrefix) || IsServerRequest(name)
}

// IsServerRequest reports whether name is a request the server makes of
// the client, such as server:elicitation.
func IsServerRequest(name string) bool { return strings.HasPrefix(name, ServerPrefix) }

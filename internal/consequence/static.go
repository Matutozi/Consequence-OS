package consequence

import (
	"context"
	"fmt"
)

// Static assesses calls from a fixed list of tools and how reversible each
// is: the tools map in consequence.yaml. It never fails. A tool that isn't
// listed counts as irreversible; a resource or prompt that isn't listed
// counts as a read, since reading changes nothing.
type Static struct {
	tools map[string]Reversibility
}

// NewStatic copies tools, so later changes to the caller's map can't
// affect it. Values must be valid; policy.NewEngine checks them first.
func NewStatic(tools map[string]Reversibility) Static {
	s := Static{tools: make(map[string]Reversibility, len(tools))}
	for name, r := range tools {
		s.tools[name] = r
	}
	return s
}

// Assess implements Resolver.
func (s Static) Assess(_ context.Context, tool string, _ map[string]any) (Assessment, error) {
	r, listed := s.tools[tool]
	var reason string
	switch {
	case listed:
		reason = fmt.Sprintf("%s is listed as %s in the tools map.", tool, describe(r))
	case IsServerRequest(tool):
		r = Read
		reason = "Requests from the server that aren't in the tools map count as reads: the client shows them to the user."
	case IsRead(tool):
		r = Read
		reason = "Resources and prompts that aren't in the tools map count as reads."
	default:
		r = None
		reason = fmt.Sprintf("%s isn't in the tools map, so it counts as irreversible.", tool)
	}
	return Assessment{Score: DefaultScore(r), Reversibility: r, Reasons: []string{reason}, Source: SourceConfig}, nil
}

// DefaultScore is the score Static gives each reversibility.
func DefaultScore(r Reversibility) int {
	switch r {
	case Read:
		return DefaultReadScore
	case Reversible:
		return DefaultReversibleScore
	}
	// Compensable is scored as irreversible until undo contracts (phase 5)
	// can show the compensation actually runs.
	return DefaultIrreversibleScore
}

// describe names r the way the tools map does.
func describe(r Reversibility) string {
	switch r {
	case Read:
		return "a read"
	case None:
		return "irreversible"
	}
	return string(r)
}

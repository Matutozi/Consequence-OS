package consequence

import (
	"context"
	"errors"
	"slices"
)

// Max combines resolvers and keeps the worst view of each call: the highest
// score, the hardest reversibility, the widest blast radius, and every data
// class, owner, target and reason any of them gave. One resolver can then
// raise a score but never lower it, so adding a computed map to the config
// can only make the policy stricter. If any resolver fails, Max fails.
type Max []Resolver

// Assess implements Resolver.
func (m Max) Assess(ctx context.Context, tool string, args map[string]any) (Assessment, error) {
	if len(m) == 0 {
		return Assessment{}, errors.New("consequence: Max has no resolvers")
	}
	var out Assessment
	for i, r := range m {
		a, err := r.Assess(ctx, tool, args)
		if err != nil {
			return Assessment{}, err
		}
		if i == 0 || a.Score > out.Score {
			// The resolver with the highest score names the source; on a tie
			// the earlier one keeps it.
			out.Score, out.Source, out.MapHash = a.Score, a.Source, a.MapHash
		}
		if i == 0 || severity[a.Reversibility] > severity[out.Reversibility] {
			out.Reversibility = a.Reversibility
		}
		out.BlastRadius = max(out.BlastRadius, a.BlastRadius)
		out.DataClasses = union(out.DataClasses, a.DataClasses)
		out.Owners = union(out.Owners, a.Owners)
		out.Targets = union(out.Targets, a.Targets)
		out.Reasons = union(out.Reasons, a.Reasons)
	}
	return out, nil
}

// union appends the items of b that aren't in a yet, keeping their order.
func union(a, b []string) []string {
	for _, s := range b {
		if !slices.Contains(a, s) {
			a = append(a, s)
		}
	}
	return a
}

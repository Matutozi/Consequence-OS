package shadowscore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/matutozi/consequence-os/internal/config"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/policytest"
	"github.com/matutozi/consequence-os/internal/store"
)

// Row is one case decided twice: once on the tools map's score, as the
// gate decides today, and once on the context score.
type Row struct {
	Case    policytest.Case // Want is the decision you'd want
	Today   policy.Decision
	Context policy.Decision
	Shadow  Result
}

// Verdict names how the two decisions compare with the one wanted.
func (r Row) Verdict() string {
	today, ctx := r.Today.Action == r.Case.Want, r.Context.Action == r.Case.Want
	switch {
	case today && ctx:
		return "both right"
	case ctx:
		return "score fixes it"
	case today:
		return "score breaks it"
	}
	return "both wrong"
}

// Compare decides every case in f with the policy in cfg, on today's score
// and on the context score from spec. Cases with earlier calls (before:)
// aren't supported: limits aren't what this compares.
func Compare(ctx context.Context, cfg *config.Config, f *policytest.File, spec Spec) ([]Row, error) {
	engine, err := cfg.NewEngine()
	if err != nil {
		return nil, err
	}
	at := time.Now()
	if f.At != "" {
		if at, err = time.Parse(time.RFC3339, f.At); err != nil {
			return nil, fmt.Errorf("at %q must be a time like 2026-11-16T10:00:00Z", f.At)
		}
	}
	var rows []Row
	for i, c := range f.Cases {
		if c.Name == "" {
			c.Name = fmt.Sprintf("case %d", i+1)
		}
		if len(c.Before) > 0 {
			return nil, fmt.Errorf("%s: earlier calls (before:) aren't supported here", c.Name)
		}
		if c.At != "" {
			return nil, fmt.Errorf("%s: set the time with the file's at:, not the case's", c.Name)
		}
		args, err := f.CaseArgs(c)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Name, err)
		}
		agent := c.Agent
		if agent == "" {
			agent = "test-agent"
		}
		call := policy.Call{AgentID: agent, Tool: c.Tool, Args: args, At: at}
		row := Row{Case: c}
		if row.Today, err = engine.Decide(ctx, call, store.NewMemory()); err != nil {
			return nil, fmt.Errorf("%s: %w", c.Name, err)
		}
		base := row.Today.Consequence
		row.Shadow = spec.Assess(base, c.Tool, args)
		call.Consequence = row.Shadow.Assessment(base)
		if row.Context, err = engine.Decide(ctx, call, store.NewMemory()); err != nil {
			return nil, fmt.Errorf("%s: %w", c.Name, err)
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, errors.New("no cases")
	}
	return rows, nil
}

// Print writes each case with both decisions and the factors behind the
// context score, then counts the verdicts.
func Print(w io.Writer, rows []Row) {
	counts := map[string]int{}
	for _, r := range rows {
		v := r.Verdict()
		counts[v]++
		fmt.Fprintf(w, "%s\n", r.Case.Name)
		fmt.Fprintf(w, "  want     %s\n", r.Case.Want)
		fmt.Fprintf(w, "  today    %-5s by %-24s score %d\n", r.Today.Action, r.Today.Rule, r.Today.Consequence.Score)
		fmt.Fprintf(w, "  context  %-5s by %-24s score %d\n", r.Context.Action, r.Context.Rule, r.Shadow.Score)
		if len(r.Shadow.Factors) > 0 {
			parts := make([]string, 0, len(r.Shadow.Factors))
			for _, f := range r.Shadow.Factors {
				parts = append(parts, f.Reason)
			}
			fmt.Fprintf(w, "           %d, %s\n", r.Shadow.Base, strings.Join(parts, "; "))
		}
		fmt.Fprintf(w, "  => %s\n\n", v)
	}
	fmt.Fprintf(w, "%d cases:", len(rows))
	for _, v := range []string{"both right", "score fixes it", "score breaks it", "both wrong"} {
		fmt.Fprintf(w, " %s %d,", v, counts[v])
	}
	fmt.Fprintln(w)
}

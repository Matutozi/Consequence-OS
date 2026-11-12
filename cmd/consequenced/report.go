package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/config"
)

// consequenced -report summarises the audit log over a period: how many
// calls went ahead, and which rules stopped calls, or in observe mode
// would have, how often and on which tools. In observe mode it is the
// answer to "what would ConsequenceOS have held last week?".

// parseSince reads -since: a Go duration like 36h, or a number of days
// like 7d.
func parseSince(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d, nil
	}
	return 0, fmt.Errorf("-since %q must be a number of days like 7d, or a duration like 36h", s)
}

// callOutcomes are the outcomes of calls, as against approval decisions
// and bookkeeping such as tool pins.
var callOutcomes = []audit.Outcome{
	audit.OutcomeForwarded, audit.OutcomeObserved, audit.OutcomeBlocked, audit.OutcomeHeld,
	audit.OutcomeAskedUser, audit.OutcomeRejected,
}

// stopped says how an entry's call was stopped, or would have been, or ""
// when it went ahead.
func stopped(e audit.Entry) string {
	switch e.Outcome {
	case audit.OutcomeBlocked:
		return "blocked"
	case audit.OutcomeHeld:
		return "held for approval"
	case audit.OutcomeAskedUser:
		return "asked the user"
	case audit.OutcomeRejected:
		return "rejected"
	case audit.OutcomeObserved:
		// "observe mode: would have been refused: why; note" says "would have been refused".
		how := strings.TrimPrefix(e.Detail, "observe mode: ")
		if i := strings.IndexAny(how, ":;"); i >= 0 {
			how = how[:i]
		}
		if how == "" {
			return "observed"
		}
		return how
	}
	return ""
}

func printReport(ctx context.Context, out io.Writer, cfg *config.Config, since time.Duration, now time.Time) error {
	st, err := openForReading(ctx, cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	start := now.Add(-since)

	counts := map[audit.Outcome]int{}
	type row struct {
		rule, how string
		n         int
		tools     map[string]int
	}
	rows := map[string]*row{}
	calls := 0
	err = st.ForEachAudit(ctx, func(e audit.Entry) error {
		if e.Time.Before(start) {
			return nil
		}
		counts[e.Outcome]++
		how := stopped(e)
		for _, o := range callOutcomes {
			if e.Outcome == o {
				calls++
			}
		}
		if how == "" {
			return nil
		}
		rule := e.Rule
		if rule == "" {
			rule = "(before the policy)"
		}
		key := rule + "\x00" + how
		r := rows[key]
		if r == nil {
			r = &row{rule: rule, how: how, tools: map[string]int{}}
			rows[key] = r
		}
		r.n++
		r.tools[e.Tool]++
		return nil
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "From %s to %s (%s): %d calls\n", start.Local().Format("2006-01-02 15:04"), now.Local().Format("2006-01-02 15:04"), describeSince(since), calls)
	if cfg.Observe() {
		fmt.Fprintln(out, "Observe mode: calls the policy would have stopped went ahead, and show as \"would have been ...\".")
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', tabwriter.AlignRight)
	for _, o := range append(callOutcomes, audit.OutcomeApproved, audit.OutcomeDeclined, audit.OutcomeExpired) {
		if counts[o] > 0 {
			fmt.Fprintf(tw, "  %s\t%d\t\n", o, counts[o])
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintln(out, "\nNo call was stopped, and none would have been.")
		return nil
	}

	list := make([]*row, 0, len(rows))
	for _, r := range rows {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].rule+list[i].how < list[j].rule+list[j].how
	})
	fmt.Fprintln(out, "\nStopped, or would have been, by rule:")
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  RULE\tCALLS\tWHAT\tTOOLS")
	for _, r := range list {
		fmt.Fprintf(tw, "  %s\t%d\t%s\t%s\n", r.rule, r.n, r.how, topTools(r.tools, 3))
	}
	return tw.Flush()
}

// topTools names the n tools seen most, with how often, and how many more.
func topTools(tools map[string]int, n int) string {
	names := make([]string, 0, len(tools))
	for t := range tools {
		names = append(names, t)
	}
	sort.Slice(names, func(i, j int) bool {
		if tools[names[i]] != tools[names[j]] {
			return tools[names[i]] > tools[names[j]]
		}
		return names[i] < names[j]
	})
	var parts []string
	for i, t := range names {
		if i == n {
			parts = append(parts, fmt.Sprintf("and %d more", len(names)-n))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%d)", t, tools[t]))
	}
	return strings.Join(parts, ", ")
}

func describeSince(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		days := int(d / (24 * time.Hour))
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	return d.String()
}

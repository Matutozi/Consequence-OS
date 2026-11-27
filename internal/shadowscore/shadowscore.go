// Package shadowscore is an experiment, and nothing in the gate uses it.
// It tries the idea of a base score per tool multiplied by the consequence
// of the specific call: how many records the call touches, and whether it
// sends data outside the company. Run cmd/shadow-score to see, case by
// case, where a policy deciding on this score would differ from the same
// policy on the tools map's score, and from the decision you'd want.
//
// Every multiplier carries a reason, so each score can be traced back to
// the facts and weights that made it. See docs/shadow-score.md.
package shadowscore

import (
	"fmt"
	"math"
	"net/mail"
	"net/url"
	"strings"

	"github.com/matutozi/consequence-os/internal/consequence"
)

// Spec says which arguments carry the call's context, and how much each
// fact weighs.
type Spec struct {
	// InternalDomains are the company's own domains. A destination on one
	// of them, or a subdomain of one, stays inside.
	InternalDomains []string `yaml:"internal_domains"`
	// Tools names, per exact tool name, the arguments to read.
	Tools   map[string]Tool `yaml:"tools"`
	Weights Weights         `yaml:"weights"`
}

// Tool names a tool's context arguments. Only top-level arguments are read.
type Tool struct {
	// Records holds what the call acts on: a list (its length counts) or
	// a number.
	Records string `yaml:"records"`
	// Destination holds where data goes: an email address, a URL or a
	// domain, or a list of them.
	Destination string `yaml:"destination"`
}

// Weights are the multipliers. Zero means the default.
type Weights struct {
	Few      float64 `yaml:"few"`      // 2 records up to ManyAt (default 1.25)
	Many     float64 `yaml:"many"`     // ManyAt records or more, or a count it can't read (default 1.5)
	ManyAt   int     `yaml:"many_at"`  // default 100
	External float64 `yaml:"external"` // any destination outside, or one it can't read (default 1.5)
	Internal float64 `yaml:"internal"` // every destination inside (default 1)
}

func (w Weights) withDefaults() Weights {
	def := func(v *float64, d float64) {
		if *v == 0 {
			*v = d
		}
	}
	def(&w.Few, 1.25)
	def(&w.Many, 1.5)
	def(&w.External, 1.5)
	def(&w.Internal, 1)
	if w.ManyAt == 0 {
		w.ManyAt = 100
	}
	return w
}

// Factor is one multiplier applied to the base score, and why.
type Factor struct {
	Multiplier float64
	Reason     string
}

// Result is a call's context score.
type Result struct {
	Base    int // the tools map's score
	Factors []Factor
	Score   int // Base times every multiplier, rounded, at most 100
}

// Assess scores a call: base's score times a multiplier for each fact the
// spec names for tool. A tool the spec doesn't list keeps its base score.
func (s Spec) Assess(base consequence.Assessment, tool string, args map[string]any) Result {
	w := s.Weights.withDefaults()
	r := Result{Base: base.Score}
	t, ok := s.Tools[tool]
	if !ok {
		r.Score = base.Score
		return r
	}
	if t.Records != "" {
		r.Factors = append(r.Factors, recordsFactor(w, t.Records, args))
	}
	if t.Destination != "" {
		r.Factors = append(r.Factors, s.destinationFactor(w, t.Destination, args))
	}
	score := float64(base.Score)
	for _, f := range r.Factors {
		score *= f.Multiplier
	}
	r.Score = min(consequence.MaxScore, int(math.Round(score)))
	return r
}

// Assessment is base with the context score in place of its score, and
// the factors' reasons added, for the policy to decide on.
func (r Result) Assessment(base consequence.Assessment) consequence.Assessment {
	a := base
	a.Score = r.Score
	a.Reasons = append([]string(nil), base.Reasons...)
	for _, f := range r.Factors {
		a.Reasons = append(a.Reasons, f.Reason)
	}
	return a
}

func recordsFactor(w Weights, arg string, args map[string]any) Factor {
	n, ok := count(args[arg])
	switch {
	case !ok:
		return Factor{w.Many, fmt.Sprintf("%s doesn't give a count, so it counts as many records: ×%g", arg, w.Many)}
	case n >= w.ManyAt:
		return Factor{w.Many, fmt.Sprintf("touches %d records (%d or more): ×%g", n, w.ManyAt, w.Many)}
	case n >= 2:
		return Factor{w.Few, fmt.Sprintf("touches %d records: ×%g", n, w.Few)}
	}
	return Factor{1, fmt.Sprintf("touches %d record: ×1", n)}
}

func count(v any) (int, bool) {
	switch x := v.(type) {
	case []any:
		return len(x), true
	case float64:
		if x >= 0 && x == math.Trunc(x) {
			return int(x), true
		}
	}
	return 0, false
}

func (s Spec) destinationFactor(w Weights, arg string, args map[string]any) Factor {
	var dests []string
	switch x := args[arg].(type) {
	case string:
		dests = []string{x}
	case []any:
		for _, v := range x {
			d, ok := v.(string)
			if !ok {
				return Factor{w.External, fmt.Sprintf("%s holds something that isn't text, so it counts as outside: ×%g", arg, w.External)}
			}
			dests = append(dests, d)
		}
	}
	if len(dests) == 0 {
		return Factor{w.External, fmt.Sprintf("%s names no destination, so it counts as outside: ×%g", arg, w.External)}
	}
	for _, d := range dests {
		host := domainOf(d)
		if host == "" || !s.internal(host) {
			return Factor{w.External, fmt.Sprintf("sends to %s, outside the company: ×%g", d, w.External)}
		}
	}
	return Factor{w.Internal, fmt.Sprintf("every destination is inside the company: ×%g", w.Internal)}
}

// domainOf finds the domain in an email address, a URL or a bare domain,
// or "" when it can't.
func domainOf(d string) string {
	d = strings.TrimSpace(d)
	var host string
	switch {
	case strings.Contains(d, "://"):
		u, err := url.Parse(d)
		if err != nil {
			return ""
		}
		host = u.Hostname()
	case strings.Contains(d, "@"):
		a, err := mail.ParseAddress(d)
		if err != nil {
			return ""
		}
		host = a.Address[strings.LastIndex(a.Address, "@")+1:]
	default:
		host = d
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func (s Spec) internal(host string) bool {
	for _, d := range s.InternalDomains {
		d = strings.TrimSuffix(strings.ToLower(d), ".")
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

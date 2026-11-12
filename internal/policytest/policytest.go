// Package policytest runs a table of calls against a policy and checks
// each decision: consequenced -test. Teams can then change a policy, and
// see in CI what the change does, before trusting it with live calls.
//
// A test file names the policy (or takes -config), and lists cases: a
// call, when it's made, calls made before it (for limit rules), and the
// decision expected. For a Claude Code hook policy, the arguments are
// Claude Code's tool_input, and the hook's derived arguments (compound,
// in_project...) are added as the hook adds them.
package policytest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/matutozi/consequence-os/internal/config"
	"github.com/matutozi/consequence-os/internal/hook"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/store"
)

// File is a test file.
type File struct {
	// Config is the policy to test: a config file, relative to the test
	// file. -config, when given, wins.
	Config string `yaml:"config"`
	// At is when calls are made unless a case says otherwise, so rules
	// with time windows give the same answer every run. Empty means now.
	At string `yaml:"at"`
	// Hook is "claude-code" when the cases are Claude Code tool calls.
	Hook string `yaml:"hook"`
	// Project is the project directory for hook cases, and their working
	// directory unless a case gives one.
	Project string `yaml:"project"`
	// RequireEveryRule fails the run when a rule is reached by no case.
	RequireEveryRule bool   `yaml:"require_every_rule"`
	Cases            []Case `yaml:"cases"`
}

// Case is one call and the decision it should get.
type Case struct {
	Name  string    `yaml:"name"`
	Tool  string    `yaml:"tool"`
	Args  yaml.Node `yaml:"args"` // an object; see jsonValue
	At    string    `yaml:"at"`
	Agent string    `yaml:"agent"` // limits count per agent; default "test-agent"
	Cwd   string    `yaml:"cwd"`   // hook cases: where Claude Code works; default project
	// Set gives arguments after the hook's derived ones are added, for
	// facts that depend on the machine, such as via_symlink: true.
	Set yaml.Node `yaml:"set"`
	// Before lists calls made earlier, which count towards limit rules.
	Before []Earlier `yaml:"before"`
	// Want is the action expected: allow, ask or deny.
	Want policy.Action `yaml:"want"`
	// Rule, when set, is the rule expected to decide.
	Rule string `yaml:"rule"`
}

// Earlier is a call made before a case, counted for limits.
type Earlier struct {
	Tool  string        `yaml:"tool"` // default: the case's tool
	Args  yaml.Node     `yaml:"args"`
	Ago   time.Duration `yaml:"ago"`   // how long before the case; default a minute
	Times int           `yaml:"times"` // how many such calls; default 1
}

// Result is one case's outcome.
type Result struct {
	Case
	Got     policy.Action
	GotRule string
	Err     error // the case couldn't be run as written
}

// Passed reports whether the case got what it expected.
func (r Result) Passed() bool {
	return r.Err == nil && r.Got == r.Want && (r.Rule == "" || r.Rule == r.GotRule)
}

// Report is a whole run.
type Report struct {
	Results []Result
	// Unreached lists the rules no case was decided by, in policy order.
	Unreached []string
	// RequireEveryRule is the file's setting, so Failed can tell.
	RequireEveryRule bool
}

// Failed reports whether the run fails: a case that didn't pass, or a
// rule no case reached when the file requires every rule.
func (r Report) Failed() bool {
	for _, res := range r.Results {
		if !res.Passed() {
			return true
		}
	}
	return r.RequireEveryRule && len(r.Unreached) > 0
}

// Read reads a test file strictly: an unknown field is an error, so a
// typo like "wants:" doesn't quietly test nothing.
func Read(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s is empty", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(f.Cases) == 0 {
		return nil, fmt.Errorf("%s has no cases", path)
	}
	if f.Hook != "" && f.Hook != "claude-code" {
		return nil, fmt.Errorf("%s: hook %q: the only hook is claude-code", path, f.Hook)
	}
	if rest, ok := strings.CutPrefix(f.Config, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		f.Config = filepath.Join(home, rest)
	}
	if f.Config != "" && !filepath.IsAbs(f.Config) {
		f.Config = filepath.Join(filepath.Dir(path), f.Config)
	}
	return &f, nil
}

// Run decides each case with the policy in cfg.
func Run(ctx context.Context, cfg *config.Config, f *File, now time.Time) (Report, error) {
	engine, err := cfg.NewEngine()
	if err != nil {
		return Report{}, err
	}
	defaultAt := now
	if f.At != "" {
		if defaultAt, err = time.Parse(time.RFC3339, f.At); err != nil {
			return Report{}, fmt.Errorf("at %q must be a time like 2026-11-16T10:00:00Z", f.At)
		}
	}
	reached := map[string]bool{}
	rep := Report{RequireEveryRule: f.RequireEveryRule}
	for i, c := range f.Cases {
		if c.Name == "" {
			c.Name = fmt.Sprintf("case %d", i+1)
		}
		res := Result{Case: c}
		res.Got, res.GotRule, res.Err = run(ctx, engine, f, c, defaultAt)
		if res.Err == nil {
			reached[res.GotRule] = true
		}
		rep.Results = append(rep.Results, res)
	}
	for _, r := range cfg.Rules {
		if !reached[r.Name] {
			rep.Unreached = append(rep.Unreached, r.Name)
		}
	}
	return rep, nil
}

func run(ctx context.Context, engine *policy.Engine, f *File, c Case, defaultAt time.Time) (policy.Action, string, error) {
	switch {
	case c.Tool == "":
		return "", "", errors.New("it names no tool")
	case c.Want != policy.ActionAllow && c.Want != policy.ActionAsk && c.Want != policy.ActionDeny:
		return "", "", fmt.Errorf("want %q must be allow, ask or deny", c.Want)
	}
	at := defaultAt
	if c.At != "" {
		var err error
		if at, err = time.Parse(time.RFC3339, c.At); err != nil {
			return "", "", fmt.Errorf("at %q must be a time like 2026-11-16T10:00:00Z", c.At)
		}
	}
	agent := c.Agent
	if agent == "" {
		agent = "test-agent"
	}
	args, err := f.callArgs(c.Tool, c.Args, c.Cwd)
	if err != nil {
		return "", "", err
	}
	if c.Set.Kind != 0 {
		set, err := f.callArgs("", c.Set, "")
		if err != nil {
			return "", "", err
		}
		for k, v := range set {
			args[k] = v
		}
	}
	// Earlier calls are recorded as the gate records calls that go ahead.
	usage := store.NewMemory()
	for _, b := range c.Before {
		tool := b.Tool
		if tool == "" {
			tool = c.Tool
		}
		bArgs, err := f.callArgs(tool, b.Args, c.Cwd)
		if err != nil {
			return "", "", err
		}
		ago, times := b.Ago, b.Times
		if ago <= 0 {
			ago = time.Minute
		}
		if times <= 0 {
			times = 1
		}
		for range times {
			for _, u := range engine.UsageRecords(policy.Call{AgentID: agent, Tool: tool, Args: bArgs, At: at.Add(-ago)}) {
				if err := usage.RecordUsage(ctx, u); err != nil {
					return "", "", err
				}
			}
		}
	}
	d, err := engine.Decide(ctx, policy.Call{AgentID: agent, Tool: c.Tool, Args: args, At: at}, usage)
	if err != nil {
		return "", "", err
	}
	return d.Action, d.Rule, nil
}

// callArgs makes a case's arguments what the gate would see: JSON's
// types (see jsonValue), and for hook cases the hook's derived arguments.
func (f *File) callArgs(tool string, in yaml.Node, cwd string) (map[string]any, error) {
	args := map[string]any{}
	if in.Kind != 0 {
		v, err := jsonValue(&in)
		if err != nil {
			return nil, fmt.Errorf("args: %w", err)
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("args must be an object, at line %d", in.Line)
		}
		args = m
	}
	if f.Hook == "claude-code" && tool != "" {
		if cwd == "" {
			cwd = f.Project
		}
		hook.Derive(tool, args, cwd, f.Project)
	}
	return args, nil
}

// jsonValue converts YAML to what decoding the same call as JSON gives,
// so a case behaves as the real call would: numbers are float64, and a
// value YAML would read as a timestamp, like 2026-01-01, stays the text
// written, as a JSON string would.
func jsonValue(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return jsonValue(n.Content[0])
	case yaml.AliasNode:
		return jsonValue(n.Alias)
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("line %d: keys must be text", k.Line)
			}
			if _, dup := out[k.Value]; dup {
				return nil, fmt.Errorf("line %d: %s is given twice", k.Line, k.Value)
			}
			v, err := jsonValue(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			out[k.Value] = v
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := jsonValue(c)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	switch n.ShortTag() {
	case "!!null":
		return nil, nil
	case "!!bool", "!!int", "!!float":
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, err
		}
		switch x := v.(type) {
		case int:
			return float64(x), nil
		case int64:
			return float64(x), nil
		case uint64:
			return float64(x), nil
		}
		return v, nil
	}
	return n.Value, nil // strings, and timestamps as written
}

// Print writes the report: a line per case, then a summary.
func Print(w io.Writer, rep Report) {
	failed := 0
	for _, r := range rep.Results {
		switch {
		case r.Err != nil:
			failed++
			fmt.Fprintf(w, "FAIL  %s: %v\n", r.Name, r.Err)
		case !r.Passed():
			failed++
			want := string(r.Want)
			if r.Rule != "" {
				want += " by " + r.Rule
			}
			fmt.Fprintf(w, "FAIL  %s: got %s by %s, want %s\n", r.Name, r.Got, r.GotRule, want)
		default:
			fmt.Fprintf(w, "ok    %s: %s by %s\n", r.Name, r.Got, r.GotRule)
		}
	}
	if len(rep.Unreached) > 0 {
		label := "note"
		if rep.RequireEveryRule {
			label = "FAIL"
		}
		fmt.Fprintf(w, "%s  no case reaches these rules: %s\n", label, strings.Join(rep.Unreached, ", "))
	}
	switch {
	case failed > 0:
		fmt.Fprintf(w, "FAIL: %d of %d cases\n", failed, len(rep.Results))
	case rep.Failed():
		fmt.Fprintf(w, "FAIL: every case passed, but not every rule is tested\n")
	default:
		fmt.Fprintf(w, "ok: %d cases\n", len(rep.Results))
	}
}

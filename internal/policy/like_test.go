package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/matutozi/consequence-os/internal/consequence"
)

func TestLike(t *testing.T) {
	git := Condition{Arg: "command", Op: OpLike, Value: "git status*"}
	env := Condition{Arg: "file_path", Op: OpLike, Value: []any{"*/.env", "*/.env.*"}}
	notEnv := Condition{Arg: "file_path", Op: OpNotLike, Value: []any{"*/.env", "*/.env.*"}}
	folded := Condition{Arg: "branch", Op: OpLike, Value: "Release/*", Fold: true}
	tests := []struct {
		name string
		cond Condition
		arg  any // nil means the argument is missing
		want bool
	}{
		{"prefix", git, "git status --short", true},
		{"exact", git, "git status", true},
		{"other command", git, "git push", false},
		{"case matters without fold", git, "Git status", false},
		{"star crosses slashes", env, "/home/ada/project/.env", true},
		{"any of a list", env, "/srv/app/.env.local", true},
		{"none of a list", env, "/srv/app/main.go", false},
		{"not_like holds", notEnv, "/srv/app/main.go", true},
		{"not_like fails on a hit", notEnv, "/srv/app/.env", false},
		{"fold ignores case", folded, "release/2026-11", true},
		{"fold ignores outer spaces", folded, "  RELEASE/x ", true},
		{"fold still needs the pattern", folded, "main", false},
		{"question mark is one character", Condition{Arg: "v", Op: OpLike, Value: "v?"}, "v1", true},
		{"question mark isn't two", Condition{Arg: "v", Op: OpLike, Value: "v?"}, "v12", false},
		{"a class", Condition{Arg: "v", Op: OpLike, Value: "v[0-9]"}, "v7", true},
		{"an escaped star is literal", Condition{Arg: "v", Op: OpLike, Value: `a\*b`}, "a*b", true},
		{"an escaped star matches only a star", Condition{Arg: "v", Op: OpLike, Value: `a\*b`}, "axxb", false},
		{"like: a number isn't text", Condition{Arg: "v", Op: OpLike, Value: "*"}, 5.0, false},
		{"like: missing never matches", git, nil, false},
		{"not_like: a number isn't text", Condition{Arg: "v", Op: OpNotLike, Value: "x*"}, 5.0, false},
		{"not_like: missing never matches", notEnv, nil, false},
		// Matching swaps "/" for NUL, so NUL in a value could stand in for a "/".
		{"like: NUL never matches", Condition{Arg: "p", Op: OpLike, Value: "/srv/*"}, "\x00srv\x00x", false},
		{"not_like: NUL never matches", notEnv, "/srv/.env\x00", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cond.validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			args := map[string]any{}
			if tt.arg != nil {
				args[tt.cond.Arg] = tt.arg
			}
			if got := tt.cond.matches(args); got != tt.want {
				t.Errorf("matches(%q) = %v, want %v", tt.arg, got, tt.want)
			}
		})
	}
}

func TestLikeValidation(t *testing.T) {
	tests := []struct {
		name string
		cond Condition
		want string
	}{
		{"number", Condition{Arg: "v", Op: OpLike, Value: 5}, "needs a glob or a list of globs"},
		{"empty", Condition{Arg: "v", Op: OpLike, Value: ""}, "needs a glob"},
		{"empty list", Condition{Arg: "v", Op: OpNotLike, Value: []any{}}, "needs a glob"},
		{"list with a number", Condition{Arg: "v", Op: OpLike, Value: []any{"a*", 5}}, "needs a glob"},
		{"bad glob", Condition{Arg: "v", Op: OpLike, Value: "a[b"}, `pattern "a[b" is not a valid glob`},
		{"NUL in a glob", Condition{Arg: "v", Op: OpLike, Value: "a\x00*"}, "is not a valid glob"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cond.validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
	if err := (Condition{Arg: "v", Op: OpLike, Value: "a*", Fold: true}).validate(); err != nil {
		t.Errorf("fold with like: %v", err)
	}
}

func TestLikeOnFacts(t *testing.T) {
	a := consequence.Assessment{Score: 70, Reversibility: consequence.None, Source: consequence.SourceMap,
		Targets: []string{"table:invoices", "path:internal/billing/"}}
	tests := []struct {
		name string
		cond Condition
		want bool
	}{
		{"any target like", Condition{Arg: FactTargets, Op: OpLike, Value: "table:invoice*"}, true},
		{"no target like", Condition{Arg: FactTargets, Op: OpLike, Value: "table:users*"}, false},
		{"not_like needs no target like it", Condition{Arg: FactTargets, Op: OpNotLike, Value: "path:internal/*"}, false},
		{"not_like holds", Condition{Arg: FactTargets, Op: OpNotLike, Value: "table:users*"}, true},
		{"no targets never matches", Condition{Arg: FactOwners, Op: OpNotLike, Value: "x*"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateFact(tt.cond); err != nil {
				t.Fatal(err)
			}
			if got := tt.cond.matchFact(a); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
	err := validateFact(Condition{Arg: FactReversibility, Op: OpLike, Value: "re*"})
	if err == nil || !strings.Contains(err.Error(), "name them with in or not_in") {
		t.Errorf("like on reversibility: err = %v", err)
	}
}

func TestLikeWarnings(t *testing.T) {
	tests := []struct {
		name  string
		rules []Rule
		want  string // "" means no warning
	}{
		{
			name: "deny on a command pattern",
			rules: []Rule{
				{Name: "no-force-push", Tool: "Bash", When: Conditions{{Arg: "command", Op: OpLike, Value: "git push --force*"}}, Action: ActionDeny},
				{Name: "shell", Tool: "Bash", Action: ActionAllow},
			},
			want: `rule "no-force-push": deny matches command with a pattern, but one command can be written many ways`,
		},
		{
			name:  "ask on a command pattern, any case of the name",
			rules: []Rule{{Name: "pushes", Tool: "Bash", When: Conditions{{Arg: "Command", Op: OpLike, Value: "git push*"}}, Action: ActionAsk}},
			want:  "falls through to later rules. Allow the commands you trust",
		},
		{
			name:  "an allow on a command pattern fails closed",
			rules: []Rule{{Name: "status", Tool: "Bash", When: Conditions{{Arg: "command", Op: OpLike, Value: "git status*"}}, Action: ActionAllow}},
		},
		{
			name:  "not_like fails closed",
			rules: []Rule{{Name: "only-git", Tool: "Bash", When: Conditions{{Arg: "command", Op: OpNotLike, Value: "git *"}}, Action: ActionDeny}},
		},
		{
			name:  "a path pattern isn't a command",
			rules: []Rule{{Name: "no-env", Tool: "Write", When: Conditions{{Arg: "file_path", Op: OpLike, Value: "*/.env"}}, Action: ActionDeny}},
		},
		{
			name: "allow on a list fact with like",
			rules: []Rule{{Name: "billing-ok", Tool: "*", Action: ActionAllow,
				Consequence: Conditions{{Arg: FactTargets, Op: OpLike, Value: "path:internal/billing/*"}}}},
			want: `rule "billing-ok": allow matches targets when any one of them is like path:internal/billing/*`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := NewEngine(tt.rules, nil)
			if err != nil {
				t.Fatal(err)
			}
			got := e.Warnings()
			if tt.want == "" {
				if len(got) != 0 {
					t.Errorf("unexpected warnings: %q", got)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], tt.want) {
				t.Errorf("warnings = %q, want one containing %q", got, tt.want)
			}
		})
	}
}

// An allow-list of commands, the way P.3's starter policy will write one:
// known commands go through, and everything else asks.
func TestLikeAllowList(t *testing.T) {
	e, err := NewEngine([]Rule{
		{Name: "no-secrets", Tool: "Write", When: Conditions{{Arg: "file_path", Op: OpLike, Value: []any{"*/.env", "*/.env.*"}, Fold: true}}, Action: ActionDeny},
		{Name: "safe-git", Tool: "Bash", When: Conditions{{Arg: "command", Op: OpLike, Value: []any{"git status*", "git diff*", "git log*"}}}, Action: ActionAllow},
		{Name: "shell", Tool: "Bash", Action: ActionAsk},
	}, Levels{"Write": LevelReversible, "Bash": LevelIrreversible})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		tool, arg, value string
		want             Action
	}{
		{"Bash", "command", "git status", ActionAllow},
		{"Bash", "command", "git log --oneline -5", ActionAllow},
		{"Bash", "command", "git push --force", ActionAsk},
		{"Bash", "command", "GIT STATUS", ActionAsk}, // not the program the allow-list names
		{"Write", "file_path", "/home/ada/app/.ENV", ActionDeny},
		{"Write", "file_path", "/home/ada/app/.env.production", ActionDeny},
	}
	for _, tt := range tests {
		d, err := e.Decide(context.Background(), Call{AgentID: "a", Tool: tt.tool, Args: map[string]any{tt.arg: tt.value}}, NoUsage{})
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != tt.want {
			t.Errorf("%s %q: %s (rule %s), want %s", tt.tool, tt.value, d.Action, d.Rule, tt.want)
		}
	}
}

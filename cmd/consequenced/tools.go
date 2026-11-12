package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/matutozi/consequence-os/internal/config"
	"github.com/matutozi/consequence-os/internal/hook"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/store"
	"github.com/matutozi/consequence-os/internal/toolpin"
)

// consequenced -tools lists the pinned tool definitions, and consequenced
// -accept-tool accepts a changed one. Both work with the server's config
// and a local one: the stdio wrapper pins the tools of the servers it
// starts in its state_dir.

// loadAnyConfig loads the config for commands that work on the server's
// config and a local one alike: -tools, -accept-tool, -archive-audit and
// -verify-audit -archive. Without -config, it is ./consequence.yaml when
// there is one, and the local modes' config otherwise.
func loadAnyConfig(path string, configSet bool) (*config.Config, bool, error) {
	if !configSet {
		if _, err := os.Stat(path); err != nil {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, false, err
			}
			path = filepath.Join(home, ".consequence", "claude-code.yaml")
		}
	}
	return config.LoadAny(path, os.LookupEnv)
}

// toolService builds the pins for one server over st, or returns nil when
// the config turns pinning off.
func toolService(cfg *config.Config, st store.Store, server string, log *slog.Logger) (*toolpin.Service, error) {
	if cfg.ToolPins.Disabled {
		return nil, nil
	}
	return toolpin.New(toolpin.Options{
		Repo: st, Audit: st, Server: server, Log: log,
		AllowUnnamed: cfg.ToolPins.UnnamedArguments == config.UnnamedAllow,
		Observe:      cfg.Observe(),
	})
}

// printTools lists the pins, and warns about rules whose arguments the
// pinned schemas don't have.
func printTools(ctx context.Context, out io.Writer, cfg *config.Config, server string) error {
	st, err := openForReading(ctx, cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	pins, err := st.ListToolPins(ctx, server)
	if err != nil {
		return err
	}
	if len(pins) == 0 {
		fmt.Fprintln(out, "no tools pinned yet: tools are pinned the first time a server lists them")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	last := ""
	for _, p := range pins {
		if p.Server != last {
			if last != "" {
				fmt.Fprintln(tw)
			}
			fmt.Fprintf(tw, "%s\n  TOOL\tSTATUS\tSINCE\tHASH\n", p.Server)
			last = p.Server
		}
		status, since := "pinned", p.PinnedAt
		if p.AcceptedBy != "" {
			status = "accepted by " + p.AcceptedBy
		}
		if p.Changed() {
			status, since = "CHANGED, asks until accepted", p.SeenAt
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", p.Tool, status, since.Local().Format("2006-01-02 15:04"), shortHash(p.Hash))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if warnings := schemaWarnings(cfg.Rules, pins); len(warnings) > 0 {
		fmt.Fprintln(out)
		printWarningList(out, warnings)
	}
	return nil
}

func shortHash(h string) string {
	if len(h) > len("sha256:")+12 {
		return h[:len("sha256:")+12]
	}
	return h
}

// schemaWarnings finds rules that match an argument no pinned tool they
// cover has in its schema, so they never fire: a deny on environment for
// a tool that takes options.environment, say. Rules for every tool ("*")
// are left out, since few tools share their arguments.
func schemaWarnings(rules []policy.Rule, pins []toolpin.Pin) []string {
	var warnings []string
	for _, r := range rules {
		if r.Tool == "*" {
			continue
		}
		var schemas []any
		var names []string
		for _, p := range pins {
			if !policy.MatchTool(r.Tool, p.Tool) {
				continue
			}
			var def struct {
				InputSchema any `json:"inputSchema"`
			}
			if json.Unmarshal(p.Definition, &def) == nil {
				schemas, names = append(schemas, def.InputSchema), append(names, p.Tool)
			}
		}
		if len(schemas) == 0 {
			continue
		}
		args := make([]string, 0, len(r.When)+1)
		for _, c := range r.When {
			args = append(args, c.Arg)
		}
		if r.Limit != nil && r.Limit.Sum != "" {
			args = append(args, r.Limit.Sum)
		}
		for _, arg := range args {
			if anyHas(schemas, arg) {
				continue
			}
			w := fmt.Sprintf("rule %q: %s has no argument %s in its schema, so the rule never matches it", r.Name, strings.Join(names, ", "), arg)
			if alt := similarPaths(schemas, arg); len(alt) > 0 {
				w += "; did you mean " + strings.Join(alt, " or ") + "?"
			}
			warnings = append(warnings, w)
		}
	}
	return warnings
}

func anyHas(schemas []any, arg string) bool {
	for _, s := range schemas {
		if toolpin.Has(s, arg) {
			return true
		}
	}
	return false
}

// similarPaths lists the paths in schemas that end in the same name as
// arg, in any letter case.
func similarPaths(schemas []any, arg string) []string {
	want := arg[strings.LastIndex(arg, ".")+1:]
	seen := map[string]bool{}
	var out []string
	for _, s := range schemas {
		for _, p := range toolpin.Paths(s) {
			if strings.EqualFold(p[strings.LastIndex(p, ".")+1:], want) && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

// openForChanging opens the configured store to change it from the
// command line: the file store, or Postgres. what names the change, for
// the error when a running server holds the state_dir.
func openForChanging(ctx context.Context, cfg *config.Config, local bool, what string, log *slog.Logger) (store.Store, error) {
	if cfg.StateDir == "" && cfg.DatabaseURL == "" {
		return nil, errors.New("this needs database_url_env or state_dir: the in-memory store keeps nothing between runs")
	}
	if cfg.StateDir == "" {
		return store.OpenPostgres(ctx, cfg.DatabaseURL)
	}
	st, err := store.OpenFile(cfg.StateDir, store.FileOptions{Log: log, LockTimeout: hook.DefaultLockTimeout})
	if errors.Is(err, store.ErrLocked) && !local {
		return nil, fmt.Errorf("%w; the server holds its state_dir while it runs, so stop it, %s, and start it again", err, what)
	}
	return st, err
}

// runAcceptTool shows a tool's waiting change and, if the person types
// yes on the terminal, accepts it. Like -approve, it asks on the terminal
// itself, so an agent running commands can't accept a change to a tool it
// uses.
func runAcceptTool(ctx context.Context, cfg *config.Config, local bool, tool, server string, out io.Writer) error {
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	open := func() (store.Store, error) {
		if !local && cfg.StateDir == "" && cfg.DatabaseURL == "" {
			return nil, errors.New("this server keeps its pins in memory, where only it can change them; a restart pins every tool afresh")
		}
		return openForChanging(ctx, cfg, local, "accept the change", log)
	}

	st, err := open()
	if err != nil {
		return err
	}
	pins, err := st.ListToolPins(ctx, server)
	st.Close() // not held while the person reads and answers
	if err != nil {
		return err
	}
	var waiting []toolpin.Pin
	for _, p := range pins {
		if p.Tool == tool && p.Changed() {
			waiting = append(waiting, p)
		}
	}
	switch len(waiting) {
	case 0:
		return fmt.Errorf("no change to %s is waiting; consequenced -tools lists the pinned tools", tool)
	case 1:
	default:
		var servers []string
		for _, p := range waiting {
			servers = append(servers, "  "+p.Server)
		}
		return fmt.Errorf("%s changed on more than one server; pick one with -server:\n%s", tool, strings.Join(servers, "\n"))
	}
	p := waiting[0]
	fmt.Fprintf(out, "%s on %s\n  pinned:  %s, %s\n  changed: %s, first listed %s\n\n%s\n",
		p.Tool, p.Server, p.Hash, p.PinnedAt.Local().Format("2006-01-02 15:04:05"),
		p.Seen, p.SeenAt.Local().Format("2006-01-02 15:04:05"), toolpin.Diff(p.Definition, p.SeenDefinition))

	term, err := openTerminal()
	if err != nil {
		return errors.New("-accept-tool asks you on the terminal, and there is none here. That's on purpose: an agent running commands has no terminal, so it can't accept a change to a tool it uses. Run it yourself, in a terminal")
	}
	defer term.Close()
	fmt.Fprintf(term, "Read the change above. Type yes to accept it for %s: ", p.Tool)
	answer, _ := bufio.NewReader(term).ReadString('\n')
	if strings.TrimSpace(answer) != "yes" {
		fmt.Fprintln(out, "Nothing accepted.")
		return nil
	}

	st, err = open()
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := toolpin.Accept(ctx, st, st, p.Server, p.Tool, p.Seen, localUser(), time.Now()); err != nil {
		return err
	}
	fmt.Fprintf(out, "Accepted. %s is listed again, and its calls are decided by your rules.\n", p.Tool)
	return nil
}

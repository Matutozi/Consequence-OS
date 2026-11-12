package hook

import (
	"bufio"
	_ "embed" // for the starter policy
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//go:embed starter.yaml
var starter string

// Starter returns the starter policy for a config kept in dir: its state
// lives in dir/state, and the rules keep the agent out of dir. The hook
// resolves symlinks in paths before matching, so the rule names dir with
// its symlinks resolved too.
func Starter(dir string) string {
	return strings.NewReplacer(
		"{{STATE_DIR}}", yamlQuote(filepath.Join(dir, "state")),
		// Inside a single-quoted YAML string, a glob's backslashes are literal.
		`"{{CONSEQUENCE_DIR}}/*"`, yamlQuote(globEscape(resolveDir(dir))+"/*"),
	).Replace(starter)
}

// InitOptions configures Init.
type InitOptions struct {
	ConfigPath   string // where the policy goes; its directory holds the state too
	SettingsPath string // the Claude Code settings file to add the hook to
	Command      string // the command the hook runs
	Yes          bool   // add the hook without asking
	In           io.Reader
	Out          io.Writer
}

// Init sets up the Claude Code hook. It writes the starter policy, unless
// there is one already, and adds the hook to the settings file after
// showing the change and asking. Other settings and hooks stay as they
// were. Saying no is not an error: nothing is written.
func Init(opts InitOptions) error {
	out := opts.Out
	if err := writeStarter(opts.ConfigPath, out); err != nil {
		return err
	}

	current, err := os.ReadFile(opts.SettingsPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	updated, added, err := addHook(current, opts.Command)
	if err != nil {
		return fmt.Errorf("%s can't be changed safely, so it was left alone: %w", opts.SettingsPath, err)
	}
	if !added {
		fmt.Fprintf(out, "The hook is already set up in %s.\n", opts.SettingsPath)
		return nil
	}
	entry, _ := formatOrdered(hookEntry(opts.Command))
	fmt.Fprintf(out, "\nTo run the policy on every tool call, this goes into hooks.PreToolUse in %s:\n\n%s\n", opts.SettingsPath, indent(entry))
	if len(current) > 0 {
		fmt.Fprintln(out, "Everything else in the file stays as it is.")
	}
	if !opts.Yes && !confirm(opts.In, out, "Add it? [y/N] ") {
		fmt.Fprintf(out, "Left %s unchanged. Add the entry yourself, or run this again.\n", opts.SettingsPath)
		return nil
	}
	if err := writeFileAtomic(opts.SettingsPath, updated, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "Added the hook to %s.\n", opts.SettingsPath)
	return nil
}

// writeStarter writes the starter policy, unless one is there already.
func writeStarter(path string, out io.Writer) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		fmt.Fprintf(out, "Keeping your policy at %s.\n", path)
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := f.WriteString(Starter(dir)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(out, "Wrote the starter policy to %s.\n", path)
	return nil
}

func confirm(in io.Reader, out io.Writer, prompt string) bool {
	fmt.Fprint(out, prompt)
	if in == nil {
		fmt.Fprintln(out)
		return false
	}
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func indent(b []byte) string {
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	return "    " + strings.Join(lines, "\n    ") + "\n"
}

// Command returns the hook command that runs exe on the policy at
// configPath, quoted for the shell Claude Code runs it with.
func Command(exe, configPath string) string {
	return ShellQuote(exe) + " -hook claude-code -config " + ShellQuote(configPath)
}

// ShellQuote quotes s for a POSIX shell when it needs it.
func ShellQuote(s string) string {
	safe := s != ""
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_-./:@%+=,", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// yamlQuote writes s as a single-quoted YAML string, where only ' needs
// escaping (as ”).
func yamlQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// globEscape escapes the characters a glob treats specially.
func globEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`).Replace(s)
}

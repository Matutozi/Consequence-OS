// Command consequenced is the ConsequenceOS proxy server.
//
//	consequenced -config consequence.yaml            run the server
//	             [-listen 0.0.0.0:8080]              ...on this address (or $CONSEQUENCE_LISTEN)
//	consequenced -check                              validate config, print a summary, exit
//	consequenced -tool payments.refund -args '{...}' show the assessment and policy decision for one call
//	             [-at 2026-11-02T22:00:00Z]          ...as if made at that time
//	consequenced -verify-audit                       check the stored audit log's hash chain
//	consequenced -tools                              list the pinned tool definitions
//	consequenced -accept-tool notes.read             accept a changed tool definition, after asking on the terminal
//	consequenced -genkeys                            print fresh receipt signing keys
//	consequenced -jwks                               print every public key the config knows, for a key rotation
//	consequenced -version                            print the version
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/config"
	"github.com/matutozi/consequence-os/internal/gate"
	"github.com/matutozi/consequence-os/internal/hook"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/proxy"
	"github.com/matutozi/consequence-os/internal/receipt"
	"github.com/matutozi/consequence-os/internal/store"
	"github.com/matutozi/consequence-os/internal/toolpin"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// version is set when release builds are made, with
// -ldflags "-X main.version=v0.1.0"; a plain go build says "dev".
var version = "dev"

func main() {
	// The context is cancelled on Ctrl-C or SIGTERM, which triggers a clean shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Keeping the real work in run() makes it easy to return errors instead
	// of calling os.Exit from deep inside the program.
	err := run(ctx, os.Args[1:], os.Stdout)
	var code exitCode
	switch {
	case errors.As(err, &code):
		os.Exit(int(code)) // the hook has already written its answer
	case err != nil && hookMode(os.Args[1:]):
		// Claude Code lets the call run on any exit code but 2, so even a
		// mistyped flag in the hook's command must block.
		fmt.Fprintln(os.Stderr, "ConsequenceOS blocked this call:", err)
		os.Exit(hook.ExitBlock)
	case err != nil:
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// exitCode is returned by run when the process must exit with that code.
type exitCode int

func (c exitCode) Error() string { return fmt.Sprintf("exit status %d", int(c)) }

// hookMode reports whether the arguments ask for a hook.
func hookMode(args []string) bool {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue // a flag's value
		}
		if a = strings.TrimLeft(a, "-"); a == "hook" || strings.HasPrefix(a, "hook=") {
			return true
		}
	}
	return false
}

// stdin and stderr are variables so tests can stand in for them.
var (
	stdin  io.Reader = os.Stdin
	stderr io.Writer = os.Stderr
)

func run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("consequenced", flag.ContinueOnError)
	configPath := fs.String("config", "consequence.yaml", "path to the config file")
	listen := fs.String("listen", "", "address to listen on, e.g. 0.0.0.0:8080; overrides $"+config.ListenEnv+" and the config file")
	check := fs.Bool("check", false, "validate the config, print a summary and exit")
	tool := fs.String("tool", "", "evaluate a call to this tool against the policy and exit")
	toolArgs := fs.String("args", "{}", "JSON arguments for -tool")
	at := fs.String("at", "", "for -tool: decide as if the call came at this RFC 3339 time (default now)")
	genKeys := fs.Bool("genkeys", false, "print fresh receipt signing keys as env var lines and exit")
	printJWKS := fs.Bool("jwks", false, "print every public key this config knows, current and previous, as one line of JSON: receipts.previous_keys_env after the next rotation")
	showVersion := fs.Bool("version", false, "print the version and exit")
	verifyAudit := fs.Bool("verify-audit", false, "check the stored audit log's hash chain and exit; fails if it was tampered with")
	auditHead := fs.String("audit-head", "", "with -verify-audit: a signed head saved from GET /v1/audit/head; the log must still contain it")
	hookName := fs.String("hook", "", "run as a hook for this agent (claude-code): read one tool call on stdin, answer on stdout, exit 2 to block")
	initName := fs.String("init", "", "set up the hook for this agent (claude-code): write a starter policy and add the hook to its settings")
	global := fs.Bool("global", false, "with -init: add the hook to ~/.claude/settings.json, for every project, instead of this project's .claude/settings.local.json")
	yes := fs.Bool("yes", false, "with -init: change the settings without asking")
	stdioMode := fs.Bool("stdio", false, "wrap a local MCP server: start the command after --, and check every call to it")
	approveID := fs.String("approve", "", "approve a held call by its ID (apr_...), asking you on the terminal first")
	reject := fs.Bool("reject", false, "with -approve: reject the call instead")
	showLog := fs.Bool("log", false, "print recent decisions from the audit log and exit")
	logCount := fs.Int("n", 20, "with -log: how many decisions to print")
	listTools := fs.Bool("tools", false, "list the pinned tool definitions, and rules whose arguments their schemas don't have, and exit")
	acceptTool := fs.String("accept-tool", "", "accept the changed definition of this tool, asking you on the terminal first")
	serverName := fs.String("server", "", "with -tools or -accept-tool: only this server's tools, named as -tools shows it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	configSet := false
	fs.Visit(func(f *flag.Flag) { configSet = configSet || f.Name == "config" })
	local := *hookName != "" || *initName != "" || *stdioMode || *approveID != ""
	if local && !configSet {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		*configPath = filepath.Join(home, ".consequence", "claude-code.yaml")
	}
	if *initName != "" {
		return runInit(*initName, *configPath, *global, *yes, out)
	}
	if *listTools || *acceptTool != "" {
		cfg, isLocal, err := loadToolsConfig(*configPath, configSet)
		if err != nil {
			return err
		}
		if *acceptTool != "" {
			return runAcceptTool(ctx, cfg, isLocal, *acceptTool, *serverName, out)
		}
		return printTools(ctx, out, cfg, *serverName)
	}
	if *stdioMode || *approveID != "" {
		cfg, err := config.LoadLocal(*configPath, os.LookupEnv)
		if err != nil {
			return err
		}
		approveCmd := func(id string) string {
			cmd := "consequenced -approve " + id
			if configSet {
				cmd += " -config " + hook.ShellQuote(*configPath)
			}
			return cmd
		}
		if *approveID != "" {
			return runApprove(ctx, cfg, *approveID, *reject, out)
		}
		return runStdio(ctx, cfg, fs.Args(), approveCmd, out)
	}
	if *hookName != "" {
		if *auditHead != "" {
			return errors.New("-audit-head needs the server's config: the hook has no signing keys")
		}
		return runHook(ctx, hookRun{name: *hookName, configPath: *configPath, check: *check, verifyAudit: *verifyAudit, log: *showLog, n: *logCount}, out)
	}
	if *showVersion {
		fmt.Fprintln(out, "consequenced", version)
		return nil
	}
	if *genKeys {
		return printKeys(out)
	}

	cfg, err := config.LoadEnv(*configPath, withListen(*listen))
	if err != nil {
		return err
	}
	engine, err := cfg.NewEngine()
	if err != nil {
		return err
	}

	switch {
	case *showLog:
		return printLog(ctx, out, cfg, *logCount)
	case *verifyAudit:
		return checkAuditChain(ctx, out, cfg, *auditHead)
	case *tool != "":
		return explain(out, engine, *tool, *toolArgs, *at)
	case *printJWKS:
		keys, err := loadKeys(cfg)
		if err != nil {
			return err
		}
		line, err := json.Marshal(keys.All())
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\n", line)
		return nil
	case *check:
		if _, err := loadKeys(cfg); err != nil {
			return err
		}
		printSummary(out, cfg)
		printWarnings(out, cfg, engine)
		return nil
	}
	return serve(ctx, cfg, engine)
}

// hookRun is what -hook was asked to do.
type hookRun struct {
	name, configPath        string
	check, verifyAudit, log bool
	n                       int
}

// runHook answers one Claude Code tool call. With check, it checks the
// hook's config and prints a summary instead; with verifyAudit, it checks
// the hook's audit log; with log, it prints recent decisions.
func runHook(ctx context.Context, h hookRun, out io.Writer) error {
	if h.name != "claude-code" {
		return fmt.Errorf("-hook %q: the only hook is claude-code", h.name)
	}
	if !h.check && !h.verifyAudit && !h.log {
		code := hook.Run(ctx, stdin, out, stderr, hook.Options{ConfigPath: h.configPath, LookupEnv: os.LookupEnv})
		if code != hook.ExitOK {
			return exitCode(code)
		}
		return nil
	}
	cfg, err := config.LoadLocal(h.configPath, os.LookupEnv)
	if err != nil {
		return err
	}
	switch {
	case h.verifyAudit:
		return checkAuditChain(ctx, out, cfg, "")
	case h.log:
		return printLog(ctx, out, cfg, h.n)
	}
	return printHookSummary(out, cfg)
}

func printHookSummary(out io.Writer, cfg *config.Config) error {
	engine, err := cfg.NewEngine()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "config OK for the Claude Code hook\n  state_dir:         %s\n  agent:             %s (owner %s)\n",
		cfg.StateDir, cfg.LocalAgent.ID, cfg.LocalAgent.OwnerID)
	printPolicy(out, cfg)
	printWarningList(out, append(engine.Warnings(), hook.Warnings(cfg.Rules)...))
	return nil
}

// runInit sets up the Claude Code hook, then checks the result.
func runInit(name, configPath string, global, yes bool, out io.Writer) error {
	if name != "claude-code" {
		return fmt.Errorf("-init %q: the only hook is claude-code", name)
	}
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	settings := filepath.Join(".claude", "settings.local.json")
	if global {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		settings = filepath.Join(home, ".claude", "settings.json")
	}
	if settings, err = filepath.Abs(settings); err != nil {
		return err
	}
	err = hook.Init(hook.InitOptions{
		ConfigPath: configPath, SettingsPath: settings, Command: hook.Command(executable(), configPath),
		Yes: yes, In: stdin, Out: out,
	})
	if err != nil {
		return err
	}
	cfg, err := config.LoadLocal(configPath, os.LookupEnv)
	if err != nil {
		return fmt.Errorf("the policy at %s doesn't load: %w", configPath, err)
	}
	fmt.Fprintln(out)
	if err := printHookSummary(out, cfg); err != nil {
		return err
	}
	flagConfig := ""
	if def, err := os.UserHomeDir(); err != nil || configPath != filepath.Join(def, ".consequence", "claude-code.yaml") {
		flagConfig = " -config " + hook.ShellQuote(configPath)
	}
	fmt.Fprintf(out, "\nNext:\n"+
		"  - Restart Claude Code so it loads the hook.\n"+
		"  - See its decisions:        consequenced -hook claude-code -log%[1]s\n"+
		"  - Change the rules in %[2]s, then check them: consequenced -hook claude-code -check%[1]s\n", flagConfig, configPath)
	return nil
}

// runStdio wraps the MCP server command, checking every call to it.
func runStdio(ctx context.Context, cfg *config.Config, command []string, approveCmd func(string) string, out io.Writer) error {
	engine, err := cfg.NewEngine()
	if err != nil {
		return err
	}
	env, err := cfg.StdioEnvironment(os.LookupEnv)
	if err != nil {
		return err
	}
	// The log and the server's own stderr share ours, from different
	// goroutines, so writes take turns. MCP clients keep a server's stderr
	// as its log.
	errOut := &lockedWriter{w: stderr}
	log := slog.New(slog.NewTextHandler(errOut, nil))
	for _, w := range engine.Warnings() {
		log.Warn("policy: " + w)
	}
	server := toolpin.StdioServer(command)
	var openTools func(context.Context) (*toolpin.Service, func(), error)
	if !cfg.ToolPins.Disabled {
		openTools = func(context.Context) (*toolpin.Service, func(), error) {
			st, err := store.OpenFile(cfg.StateDir, store.FileOptions{Log: log, LockTimeout: hook.DefaultLockTimeout})
			if err != nil {
				return nil, nil, err
			}
			tools, err := toolService(cfg, st, server, log)
			if err != nil {
				st.Close()
				return nil, nil, err
			}
			return tools, st.Close, nil
		}
	}
	return proxy.RunStdio(ctx, stdin, out, proxy.StdioOptions{
		Command: command, Env: env, Stderr: errOut,
		AgentID: cfg.LocalAgent.ID, OwnerID: cfg.LocalAgent.OwnerID,
		Open:           localGate(cfg, engine, log, server),
		OpenTools:      openTools,
		ApproveCommand: approveCmd,
		AskInClient:    cfg.StdioAskInClient,
		LocalUser:      localUser(),
		Log:            log,
	})
}

// lockedWriter lets several goroutines write to one writer, a write at a time.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// localGate opens the gate for one call in a local mode: the file store,
// and approvals decided with consequenced -approve. Calls are checked
// against the pinned tools of server.
func localGate(cfg *config.Config, engine *policy.Engine, log *slog.Logger, server string) func(context.Context) (*gate.Gate, *approval.Service, func(), error) {
	return func(context.Context) (*gate.Gate, *approval.Service, func(), error) {
		st, err := store.OpenFile(cfg.StateDir, store.FileOptions{Log: log, LockTimeout: hook.DefaultLockTimeout})
		if err != nil {
			return nil, nil, nil, err
		}
		tools, err := toolService(cfg, st, server, log)
		if err != nil {
			st.Close()
			return nil, nil, nil, err
		}
		svc := localApprovals(cfg, st, log)
		g, err := gate.New(gate.Options{Engine: engine, Store: st, Approvals: svc, Tools: tools, Log: log})
		if err != nil {
			st.Close()
			return nil, nil, nil, err
		}
		return g, svc, st.Close, nil // File.Close is safe to call twice
	}
}

// localApprovals is the approval service of the local modes: nobody is
// emailed, and the person decides with consequenced -approve.
func localApprovals(cfg *config.Config, st store.Store, log *slog.Logger) *approval.Service {
	return approval.NewService(approval.Options{
		Repo: st, Audit: st,
		Approvers:  map[string][]string{cfg.LocalAgent.OwnerID: {localUser()}},
		Validity:   cfg.ApprovalValidity,
		Timeout:    cfg.ApprovalTimeout,
		MaxPending: cfg.MaxPendingApprovals,
		Notifier:   approval.NoNotifier{},
		Log:        log,
	})
}

// localUser names the person at this machine in approval decisions.
func localUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "local:" + u.Username
	}
	if name := os.Getenv("USER"); name != "" {
		return "local:" + name
	}
	return "local:unknown"
}

// openTerminal opens the terminal the person is sitting at. A variable so
// tests can stand in for it.
var openTerminal = func() (io.ReadWriteCloser, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }

// runApprove decides a held call from the local store. It shows the call,
// then asks on the terminal itself rather than stdin: a process with no
// terminal, such as an agent's shell tool, can't answer, so an agent can't
// approve its own calls.
func runApprove(ctx context.Context, cfg *config.Config, id string, reject bool, out io.Writer) error {
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	st, err := store.OpenFile(cfg.StateDir, store.FileOptions{Log: log, LockTimeout: hook.DefaultLockTimeout})
	if err != nil {
		return err
	}
	a, err := st.GetApproval(ctx, id)
	st.Close() // not held while the person reads and answers
	if err != nil {
		return fmt.Errorf("%s: %w", id, err)
	}
	fmt.Fprintf(out, "%s: %s\n  rule:      %s\n  score:     %d of 100\n", a.ID, a.Summary, a.Rule, a.Score)
	for _, r := range a.Reasons {
		fmt.Fprintf(out, "  because:   %s\n", r)
	}
	if len(a.Arguments) > 0 {
		fmt.Fprintf(out, "  arguments: %s\n", a.Arguments)
	}
	fmt.Fprintf(out, "  asked at:  %s\n", a.CreatedAt.Local().Format("2006-01-02 15:04:05"))
	if a.Status != approval.StatusPending {
		fmt.Fprintf(out, "It is already %s, so there is nothing to decide.\n", a.Status)
		return nil
	}

	term, err := openTerminal()
	if err != nil {
		return errors.New("-approve asks you on the terminal, and there is none here. That's on purpose: an agent running commands has no terminal, so it can't approve its own calls. Run it yourself, in a terminal")
	}
	defer term.Close()
	verb := "approve"
	if reject {
		verb = "reject"
	}
	fmt.Fprintf(term, "Type yes to %s %s: ", verb, a.ID)
	answer, _ := bufio.NewReader(term).ReadString('\n')
	if strings.TrimSpace(answer) != "yes" {
		fmt.Fprintln(out, "Nothing decided.")
		return nil
	}

	st, err = store.OpenFile(cfg.StateDir, store.FileOptions{Log: log, LockTimeout: hook.DefaultLockTimeout})
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := localApprovals(cfg, st, log).DecideLocally(ctx, a.ID, localUser(), !reject); err != nil {
		return fmt.Errorf("%s: %w", a.ID, err)
	}
	if reject {
		fmt.Fprintf(out, "Rejected %s.\n", a.ID)
		return nil
	}
	fmt.Fprintf(out, "Approved %s. The agent's retry of this exact call goes through once, within %s.\n", a.ID, approval.HumanDuration(cfg.ApprovalValidity))
	return nil
}

// executable is the path the hook command should run. A binary from go
// run lives in a temporary directory that is gone afterwards, so that case
// falls back to finding consequenced on the PATH.
func executable() string {
	exe, err := os.Executable()
	if err != nil || strings.Contains(exe, "go-build") || strings.HasPrefix(exe, os.TempDir()) {
		return "consequenced"
	}
	return exe
}

// withListen returns the process environment, with -listen (when given)
// standing in for CONSEQUENCE_LISTEN, so the flag beats the env var.
func withListen(listen string) config.LookupEnv {
	if listen == "" {
		return os.LookupEnv
	}
	return func(key string) (string, bool) {
		if key == config.ListenEnv {
			return listen, true
		}
		return os.LookupEnv(key)
	}
}

// serve runs the HTTP server until ctx is cancelled.
func serve(ctx context.Context, cfg *config.Config, engine *policy.Engine) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	for _, w := range cfg.Warnings() {
		log.Warn("config: " + w) // the same warnings -check prints
	}
	for _, w := range engine.Warnings() {
		log.Warn("policy: " + w)
	}
	st, err := openStore(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer st.Close() // runs when serve returns, after the server has shut down

	keys, err := loadKeys(cfg)
	if err != nil {
		return err
	}
	checker, err := receipt.NewChecker(keys, st, nil)
	if err != nil {
		return err
	}

	notifier, err := newNotifier(cfg, log)
	if err != nil {
		return err
	}
	approvals := approval.NewService(approval.Options{
		Repo:       st,
		Audit:      st,
		Approvers:  cfg.ApproversByOwner(),
		Validity:   cfg.ApprovalValidity,
		Timeout:    cfg.ApprovalTimeout,
		MaxPending: cfg.MaxPendingApprovals,
		PublicURL:  cfg.PublicURL,
		Notifier:   notifier,
		Log:        log,
	})
	tools, err := toolService(cfg, st, toolpin.HTTPServer(cfg.Upstream), log)
	if err != nil {
		return err
	}
	px, err := proxy.New(proxy.Options{
		Upstream:       cfg.Upstream,
		Agents:         cfg.Agents,
		AllowedOrigins: cfg.AllowedOrigins,
		Engine:         engine,
		Store:          st,
		Approvals:      approvals,
		Receipts:       receipt.NewIssuer(keys, cfg.PublicURL, cfg.Receipts.TTL, nil),
		Receiver:       cfg.UpstreamReceiver,
		UpstreamAuth:   cfg.UpstreamAuth,
		Tools:          tools,
		Log:            log,
	})
	if err != nil {
		return err
	}
	pages := approval.NewHandlers(approvals, log)

	// Go 1.22+ patterns can include a method and {wildcards}: "GET /approvals/{id}".
	mux := http.NewServeMux()
	mux.Handle("/mcp", px) // all methods: POST, plus GET/DELETE passed through for legacy clients
	mux.HandleFunc("GET /approvals/{id}", pages.Page)
	mux.HandleFunc("POST /approvals/{id}/decide", pages.Decide)
	mux.Handle("GET /v1/audit", audit.Handler(st, cfg.AdminToken, log))
	mux.Handle("GET /v1/audit/verify", audit.VerifyHandler(st, cfg.AdminToken, log))
	signHead := func(seq int64, hash string) ([]byte, error) {
		return keys.SignAuditHead(cfg.PublicURL, seq, hash, time.Now())
	}
	mux.Handle("GET /v1/audit/head", audit.HeadHandler(st, signHead, cfg.AdminToken, log))
	mux.Handle("POST "+verify.VerifyPath, receipt.VerifyHandler(checker, cfg.ReceiverKeys(), log))
	if len(cfg.Receivers) == 0 {
		log.Warn("no receivers configured: " + verify.VerifyPath + " refuses every call; receivers can still verify offline")
	}
	mux.Handle("GET "+verify.KeysPath, receipt.KeysHandler(keys))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// ListenAndServe blocks, so run it in a goroutine and wait for either a
	// server error or a shutdown signal. A channel passes the result back.
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	j := &janitor{approvals: approvals, store: st, keepUsage: engine.LongestWindow(), log: log, now: time.Now}
	go j.run(ctx) // stops when ctx is cancelled at shutdown
	log.Info("consequenced listening", "version", version, "mcp", "http://"+cfg.Listen+"/mcp", "upstream", cfg.Upstream,
		"agents", len(cfg.Agents), "rules", len(cfg.Rules))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// checkAuditChain verifies the stored audit log and prints the result. A
// broken chain is an error, so scripts and cron jobs can alert on the exit code.
func checkAuditChain(ctx context.Context, out io.Writer, cfg *config.Config, headFile string) error {
	if cfg.DatabaseURL == "" && cfg.StateDir == "" {
		return errors.New("-verify-audit needs database_url_env or state_dir: the in-memory store keeps no log between runs")
	}
	var v audit.ChainVerifier
	if headFile != "" {
		head, err := loadSavedHead(cfg, headFile)
		if err != nil {
			return err
		}
		v.ExpectHead(head.Seq, head.Hash)
		fmt.Fprintf(out, "saved head: entry %d, signed %s\n", head.Seq, head.SignedAt.Format(time.RFC3339))
	}
	st, err := openForReading(ctx, cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	r, err := audit.VerifyChainWith(ctx, st, &v)
	if err != nil {
		return err
	}
	if !r.Intact {
		where := ""
		if r.BrokenAt != "" {
			where = " at entry " + r.BrokenAt
		}
		fmt.Fprintf(out, "audit chain BROKEN%s: %s\n  %d entries checked before it\n", where, r.Problem, r.Checked)
		return errors.New("the audit log has been changed")
	}
	fmt.Fprintf(out, "audit chain intact: %d entries checked", r.Checked)
	if r.Unhashed > 0 {
		fmt.Fprintf(out, ", %d older entries from before chaining", r.Unhashed)
	}
	if r.Checked > 0 {
		fmt.Fprintf(out, "\n  head: entry %d, %s", r.HeadSeq, r.HeadHash)
	}
	fmt.Fprintln(out)
	return nil
}

// openForReading opens the configured store to read it: the file store
// read-only, so it works while a server or hook has it open.
func openForReading(ctx context.Context, cfg *config.Config) (store.Store, error) {
	if cfg.StateDir != "" {
		return store.OpenFile(cfg.StateDir, store.FileOptions{ReadOnly: true})
	}
	if cfg.DatabaseURL != "" {
		return store.OpenPostgres(ctx, cfg.DatabaseURL)
	}
	return nil, errors.New("this needs database_url_env or state_dir: the in-memory store keeps no log between runs")
}

// printLog prints the n most recent audit entries, oldest first, one line each.
func printLog(ctx context.Context, out io.Writer, cfg *config.Config, n int) error {
	if n <= 0 {
		return errors.New("-n must be at least 1")
	}
	st, err := openForReading(ctx, cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	entries, err := st.ListAudit(ctx, audit.Filter{Limit: n})
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Fprintln(out, "no decisions recorded yet")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tOUTCOME\tTOOL\tRULE\tSCORE\tDETAIL")
	for i := len(entries) - 1; i >= 0; i-- { // ListAudit is newest first
		e := entries[i]
		detail := e.Detail
		if e.ApprovalID != "" {
			detail = strings.TrimSpace(detail + " " + e.ApprovalID)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", e.Time.Local().Format("2006-01-02 15:04:05"), e.Outcome, e.Tool, e.Rule, e.Score, detail)
	}
	return tw.Flush()
}

// loadSavedHead reads a signed head and checks its signatures with this
// server's keys, so a forged head can't vouch for a rewritten log.
func loadSavedHead(cfg *config.Config, path string) (*verify.AuditHead, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys, err := loadKeys(cfg)
	if err != nil {
		return nil, err
	}
	// Every key the server has signed with: a head stays evidence after a
	// rotation.
	head, err := verify.VerifyAuditHead(data, keys.HeadKeys())
	if err != nil {
		return nil, fmt.Errorf("saved head %s: %w", path, err)
	}
	return head, nil
}

// newNotifier emails approvers when email is configured; otherwise it logs
// their links, which then makes the log a secret.
func newNotifier(cfg *config.Config, log *slog.Logger) (approval.Notifier, error) {
	if !cfg.Email.Enabled() {
		log.Warn("no email configured: approver links will be written to this log; treat it as secret")
		return approval.LogNotifier{Log: log}, nil
	}
	n, err := approval.NewEmailNotifier(cfg.Email.SMTPURL, cfg.Email.From, log)
	if err != nil {
		return nil, err
	}
	log.Info("approval links will be emailed", "from", cfg.Email.From)
	return n, nil
}

// openStore uses Postgres when a database URL is configured, the file
// store when a state_dir is, and memory otherwise.
func openStore(ctx context.Context, cfg *config.Config, log *slog.Logger) (store.Store, error) {
	if cfg.StateDir != "" {
		st, err := store.OpenFile(cfg.StateDir, store.FileOptions{Log: log})
		if err != nil {
			return nil, err
		}
		log.Info("using the file store", "state_dir", cfg.StateDir)
		return st, nil
	}
	if cfg.DatabaseURL == "" {
		log.Warn("no database_url_env or state_dir set: using the in-memory store, which loses everything on restart")
		return store.NewMemory(), nil
	}
	pg, err := store.OpenPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	log.Info("using Postgres store; migrations are up to date")
	return pg, nil
}

// loadKeys loads the signing keys, and the previous ones after a rotation.
func loadKeys(cfg *config.Config) (*receipt.Keys, error) {
	keys, err := receipt.LoadKeys(cfg.Receipts.Ed25519Key, cfg.Receipts.MLDSA87Key)
	if err != nil {
		return nil, fmt.Errorf("%w (generate keys with: consequenced -genkeys)", err)
	}
	if cfg.Receipts.PreviousKeysEnv != "" {
		if err := keys.AddPrevious([]byte(cfg.Receipts.PreviousKeys), cfg.Receipts.PreviousKeysUntil); err != nil {
			return nil, fmt.Errorf("env var %s (receipts.previous_keys_env): %w", cfg.Receipts.PreviousKeysEnv, err)
		}
	}
	return keys, nil
}

// printKeys prints fresh seeds in a form you can paste into a shell or .env file.
func printKeys(out io.Writer) error {
	ed, ml, err := receipt.GenerateSeeds()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "# Receipt signing keys. Keep these secret; anyone with them can issue receipts.\n")
	fmt.Fprintf(out, "CONSEQUENCE_SIGNING_KEY_ED25519=%s\nCONSEQUENCE_SIGNING_KEY_MLDSA87=%s\n", ed, ml)
	return nil
}

// explain prints the decision for one tool call, e.g. -tool payments.refund -args '{"amount":5000}'.
// There's no store here, so limit rules see an agent with no history.
func explain(out io.Writer, engine *policy.Engine, tool, rawArgs, rawAt string) error {
	var args map[string]any
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return fmt.Errorf("-args must be a JSON object: %w", err)
	}
	when := time.Now()
	if rawAt != "" {
		t, err := time.Parse(time.RFC3339, rawAt)
		if err != nil {
			return fmt.Errorf("-at must be an RFC 3339 time like 2026-11-02T22:00:00Z: %w", err)
		}
		when = t
	}
	d, err := engine.Decide(context.Background(), policy.Call{Tool: tool, Args: args, At: when}, policy.NoUsage{})
	if err != nil {
		return err
	}
	a := d.Consequence
	fmt.Fprintf(out, "tool=%s level=%s action=%s rule=%s score=%d reversibility=%s source=%s\n",
		tool, d.Level, d.Action, d.Rule, a.Score, a.Reversibility, a.Source)
	for _, reason := range a.Reasons {
		fmt.Fprintf(out, "  because: %s\n", reason)
	}
	if len(engine.UsageScopes(tool)) > 0 {
		fmt.Fprintln(out, "note: limit rules were checked as if this agent had made no calls yet")
	}
	return nil
}

func printSummary(out io.Writer, cfg *config.Config) {
	storage := "in memory (lost on restart)"
	switch {
	case cfg.DatabaseURLEnv != "":
		storage = "Postgres, URL from $" + cfg.DatabaseURLEnv
	case cfg.StateDir != "":
		storage = "files in " + cfg.StateDir
	}
	fmt.Fprintf(out, "config OK\n  listen:            %s\n  public URL:        %s\n  upstream:          %s\n"+
		"  approval timeout:  %s\n  approval validity: %s\n  receipt validity:  %s\n  admin token from:  $%s\n  storage:           %s\n",
		cfg.Listen, cfg.PublicURL, cfg.Upstream, approval.HumanDuration(cfg.ApprovalTimeout),
		approval.HumanDuration(cfg.ApprovalValidity), approval.HumanDuration(cfg.Receipts.TTL), cfg.AdminTokenEnv, storage)

	email := "off (approver links go to the server log)"
	if cfg.Email.Enabled() {
		email = "from " + cfg.Email.From + ", SMTP URL from $" + cfg.Email.SMTPURLEnv
	}
	fmt.Fprintf(out, "  approval email:    %s\n", email)
	if cfg.Receipts.PreviousKeysEnv != "" {
		when := "accepted for receipts until " + cfg.Receipts.PreviousKeysUntil.Format(time.RFC3339)
		if !time.Now().Before(cfg.Receipts.PreviousKeysUntil) {
			when = "for audit heads only (receipts stopped " + cfg.Receipts.PreviousKeysUntil.Format(time.RFC3339) + ")"
		}
		fmt.Fprintf(out, "  previous keys:     from $%s, %s\n", cfg.Receipts.PreviousKeysEnv, when)
	}
	if cfg.UpstreamAuthEnv != "" {
		fmt.Fprintf(out, "  upstream token:    from $%s, sent in place of the agent's key\n", cfg.UpstreamAuthEnv)
	}
	fmt.Fprintf(out, "  owners (%d):\n", len(cfg.Owners))
	for _, o := range cfg.Owners {
		fmt.Fprintf(out, "    - %s, approvers: %s\n", o.ID, strings.Join(o.Approvers, ", "))
	}

	fmt.Fprintf(out, "  agents (%d):\n", len(cfg.Agents))
	for _, a := range cfg.Agents {
		fmt.Fprintf(out, "    - %s (owner %s, key from $%s)\n", a.ID, a.OwnerID, a.APIKeyEnv)
	}
	if len(cfg.Receivers) == 0 {
		fmt.Fprintf(out, "  receivers (0): the verify endpoint is closed; receivers must verify offline\n")
	} else {
		fmt.Fprintf(out, "  receivers (%d), may call the verify endpoint:\n", len(cfg.Receivers))
	}
	for _, r := range cfg.Receivers {
		fmt.Fprintf(out, "    - %s (key from $%s)\n", r.ID, r.APIKeyEnv)
	}

	printPolicy(out, cfg)
}

// printPolicy prints the tools map, the rules and the default.
func printPolicy(out io.Writer, cfg *config.Config) {
	// Map iteration order is random in Go, so sort for stable output.
	tools := make([]string, 0, len(cfg.Tools))
	for name := range cfg.Tools {
		tools = append(tools, name)
	}
	sort.Strings(tools)
	fmt.Fprintf(out, "  tools (%d), unknown tools default to irreversible:\n", len(tools))
	for _, name := range tools {
		fmt.Fprintf(out, "    - %s: %s\n", name, cfg.Tools[name])
	}

	fmt.Fprintf(out, "  rules (%d), first match wins:\n", len(cfg.Rules))
	for i, r := range cfg.Rules {
		fmt.Fprintf(out, "    %d. %s: %s -> %s%s%s%s\n", i+1, r.Name, r.Tool, r.Action,
			describeConds(" when ", r.When), describeConds(" when consequence ", r.Consequence), describeExtras(r))
	}
	fmt.Fprintf(out, "  when no rule matches: calls scoring under %d are allowed, the rest ask\n", *cfg.DefaultAllowBelow)
}

// printWarnings lists rules that are valid but may let through more than
// intended. They don't make -check fail: the config is still usable.
func printWarnings(out io.Writer, cfg *config.Config, engine *policy.Engine) {
	printWarningList(out, append(cfg.Warnings(), engine.Warnings()...))
}

func printWarningList(out io.Writer, warnings []string) {
	if len(warnings) == 0 {
		return
	}
	fmt.Fprintf(out, "warnings (%d):\n", len(warnings))
	for _, w := range warnings {
		fmt.Fprintf(out, "  - %s\n", w)
	}
}

// describeExtras prints a rule's schedule and limit, if any.
func describeExtras(r policy.Rule) string {
	var parts []string
	if r.During != nil {
		parts = append(parts, "during "+r.During.String())
	}
	if r.Outside != nil {
		parts = append(parts, "outside "+r.Outside.String())
	}
	if r.Limit != nil {
		parts = append(parts, "once "+r.Limit.String())
	}
	if len(parts) == 0 {
		return ""
	}
	return ", " + strings.Join(parts, ", ")
}

func describeConds(prefix string, conds policy.Conditions) string {
	if len(conds) == 0 {
		return ""
	}
	parts := make([]string, len(conds))
	for i, c := range conds {
		parts[i] = fmt.Sprintf("%s %s %s", c.Arg, c.Op, formatValue(c.Value))
		if c.Fold {
			parts[i] += " (any case)"
		}
	}
	return prefix + strings.Join(parts, " and ")
}

// formatValue prints lists with commas; %v would print [Coleman Cables Acme Steel].
func formatValue(v any) string {
	items, ok := v.([]any)
	if !ok {
		return fmt.Sprint(v)
	}
	parts := make([]string, len(items))
	for i, item := range items {
		parts[i] = fmt.Sprint(item)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

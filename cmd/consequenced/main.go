// Command consequenced is the ConsequenceOS proxy server.
//
//	consequenced -config consequence.yaml            run the server
//	             [-listen 0.0.0.0:8080]              ...on this address (or $CONSEQUENCE_LISTEN)
//	consequenced -check                              validate config, print a summary, exit
//	consequenced -tool payments.refund -args '{...}' show the policy decision for one call
//	             [-at 2026-11-02T22:00:00Z]          ...as if made at that time
//	consequenced -verify-audit                       check the stored audit log's hash chain
//	consequenced -genkeys                            print fresh receipt signing keys
//	consequenced -version                            print the version
package main

import (
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
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/config"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/proxy"
	"github.com/matutozi/consequence-os/internal/receipt"
	"github.com/matutozi/consequence-os/internal/store"
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
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("consequenced", flag.ContinueOnError)
	configPath := fs.String("config", "consequence.yaml", "path to the config file")
	listen := fs.String("listen", "", "address to listen on, e.g. 0.0.0.0:8080; overrides $"+config.ListenEnv+" and the config file")
	check := fs.Bool("check", false, "validate the config, print a summary and exit")
	tool := fs.String("tool", "", "evaluate a call to this tool against the policy and exit")
	toolArgs := fs.String("args", "{}", "JSON arguments for -tool")
	at := fs.String("at", "", "for -tool: decide as if the call came at this RFC 3339 time (default now)")
	genKeys := fs.Bool("genkeys", false, "print fresh receipt signing keys as env var lines and exit")
	showVersion := fs.Bool("version", false, "print the version and exit")
	verifyAudit := fs.Bool("verify-audit", false, "check the stored audit log's hash chain and exit; fails if it was tampered with")
	auditHead := fs.String("audit-head", "", "with -verify-audit: a signed head saved from GET /v1/audit/head; the log must still contain it")
	if err := fs.Parse(args); err != nil {
		return err
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
	engine, err := policy.NewEngine(cfg.Rules, cfg.Tools)
	if err != nil {
		return err
	}

	switch {
	case *verifyAudit:
		return checkAuditChain(ctx, out, cfg, *auditHead)
	case *tool != "":
		return explain(out, engine, *tool, *toolArgs, *at)
	case *check:
		printSummary(out, cfg)
		return nil
	}
	return serve(ctx, cfg, engine)
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
	st, err := openStore(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer st.Close() // runs when serve returns, after the server has shut down

	keys, err := receipt.LoadKeys(cfg.Receipts.Ed25519Key, cfg.Receipts.MLDSA87Key)
	if err != nil {
		return fmt.Errorf("%w (generate keys with: consequenced -genkeys)", err)
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
		Repo:      st,
		Approvers: cfg.ApproversByOwner(),
		Validity:  cfg.ApprovalValidity,
		Timeout:   cfg.ApprovalTimeout,
		PublicURL: cfg.PublicURL,
		Notifier:  notifier,
		Log:       log,
	})
	px, err := proxy.New(proxy.Options{
		Upstream:       cfg.Upstream,
		Agents:         cfg.Agents,
		AllowedOrigins: cfg.AllowedOrigins,
		Engine:         engine,
		Store:          st,
		Approvals:      approvals,
		Receipts:       receipt.NewIssuer(keys, cfg.PublicURL, cfg.Receipts.TTL, nil),
		Log:            log,
	})
	if err != nil {
		return err
	}
	pages := approval.NewHandlers(approvals, st, log)

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
	if cfg.DatabaseURL == "" {
		return errors.New("-verify-audit needs database_url_env: the in-memory store keeps no log between runs")
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
	st, err := store.OpenPostgres(ctx, cfg.DatabaseURL)
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

// loadSavedHead reads a signed head and checks its signatures with this
// server's keys, so a forged head can't vouch for a rewritten log.
func loadSavedHead(cfg *config.Config, path string) (*verify.AuditHead, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys, err := receipt.LoadKeys(cfg.Receipts.Ed25519Key, cfg.Receipts.MLDSA87Key)
	if err != nil {
		return nil, err
	}
	jwks, err := json.Marshal(keys.JWKS())
	if err != nil {
		return nil, err
	}
	set, err := verify.ParseJWKS(jwks)
	if err != nil {
		return nil, err
	}
	head, err := verify.VerifyAuditHead(data, set)
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

// openStore uses Postgres when a database URL is configured, otherwise memory.
func openStore(ctx context.Context, cfg *config.Config, log *slog.Logger) (store.Store, error) {
	if cfg.DatabaseURL == "" {
		log.Warn("no database_url_env set: using the in-memory store, which loses everything on restart")
		return store.NewMemory(), nil
	}
	pg, err := store.OpenPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	log.Info("using Postgres store; migrations are up to date")
	return pg, nil
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
	fmt.Fprintf(out, "tool=%s level=%s action=%s rule=%s\n", tool, d.Level, d.Action, d.Rule)
	if engine.TracksUsage(tool) {
		fmt.Fprintln(out, "note: limit rules were checked as if this agent had made no calls yet")
	}
	return nil
}

func printSummary(out io.Writer, cfg *config.Config) {
	storage := "in memory (lost on restart)"
	if cfg.DatabaseURLEnv != "" {
		storage = "Postgres, URL from $" + cfg.DatabaseURLEnv
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
		fmt.Fprintf(out, "    %d. %s: %s -> %s%s%s\n", i+1, r.Name, r.Tool, r.Action, describeWhen(r.When), describeExtras(r))
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

func describeWhen(conds policy.Conditions) string {
	if len(conds) == 0 {
		return ""
	}
	parts := make([]string, len(conds))
	for i, c := range conds {
		parts[i] = fmt.Sprintf("%s %s %s", c.Arg, c.Op, formatValue(c.Value))
	}
	return " when " + strings.Join(parts, " and ")
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

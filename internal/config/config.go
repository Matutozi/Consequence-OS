// Package config loads consequence.yaml and resolves secrets from env vars.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/matutozi/consequence-os/internal/policy"
)

const (
	DefaultListen           = "127.0.0.1:8080"
	DefaultApprovalValidity = 10 * time.Minute
	DefaultApprovalTimeout  = time.Hour
	DefaultMaxPending       = 20 // approvals one agent may have waiting at once
	DefaultReceiptTTL       = 5 * time.Minute

	// ListenEnv, when set, overrides the file's listen address. The Docker
	// image sets it to 0.0.0.0:8080 so the port can be reached from outside.
	ListenEnv = "CONSEQUENCE_LISTEN"
)

// Config is the whole of consequence.yaml.
type Config struct {
	Listen           string        `yaml:"listen"`
	Upstream         string        `yaml:"upstream"`
	ApprovalValidity time.Duration `yaml:"approval_validity"` // yaml.v3 parses strings like "10m"
	ApprovalTimeout  time.Duration `yaml:"approval_timeout"`  // how long a held call waits for a decision
	// MaxPendingApprovals caps how many approvals one agent may have
	// waiting. Past it, new asks are refused instead of emailing approvers.
	MaxPendingApprovals int     `yaml:"max_pending_approvals"`
	Agents              []Agent `yaml:"agents"`

	// Receivers may call POST /v1/receipts/verify, each with its own key.
	// With none listed, receivers can only verify offline with the public keys.
	Receivers []Receiver `yaml:"receivers"`

	// UpstreamReceiver is the ID of the receiver behind upstream. Receipts
	// then name it (receipt v1), so no other receiver accepts them. Left
	// empty, receipts are v0 and any receiver with the tool accepts them.
	UpstreamReceiver string `yaml:"upstream_receiver"`

	// UpstreamAuthEnv names the env var holding a token for the upstream,
	// such as a hosted MCP server's. ConsequenceOS sends it as
	// "Authorization: Bearer <token>" in place of the agent's own key, so
	// the agent never holds it. It never appears in a log or the audit log.
	UpstreamAuthEnv string `yaml:"upstream_auth_env"`
	UpstreamAuth    string `yaml:"-"`

	Tools policy.Levels `yaml:"tools"`
	Rules []policy.Rule `yaml:"rules"`
	// DefaultAllowBelow is the consequence score under which a call no rule
	// matches is allowed. A pointer, so an explicit 0 (allow nothing by
	// default) differs from leaving it out (policy.DefaultAllowBelow).
	DefaultAllowBelow *int `yaml:"default_allow_below"`

	// AdminTokenEnv names the env var holding the token for owner endpoints
	// such as GET /v1/audit.
	AdminTokenEnv string `yaml:"admin_token_env"`
	AdminToken    string `yaml:"-"`

	// PublicURL is the base URL people use to reach this server, for approval
	// links. Defaults to http://<listen>.
	PublicURL string `yaml:"public_url"`

	// AllowedOrigins lists browser origins (e.g. "http://localhost:3000") that
	// may call /mcp. Agents aren't browsers, so the default is none.
	AllowedOrigins []string `yaml:"allowed_origins"`

	// Owners lists who may approve held calls for each owner's agents.
	Owners []Owner `yaml:"owners"`

	Receipts Receipts `yaml:"receipts"`

	// Email sends approvers their links. Without it, links go to the log.
	Email Email `yaml:"email"`

	// DatabaseURLEnv names the env var holding a Postgres URL. When neither
	// it nor StateDir is set, everything is kept in memory and lost on restart.
	DatabaseURLEnv string `yaml:"database_url_env"`
	DatabaseURL    string `yaml:"-"`

	// StateDir is a directory for the file store: state kept on this
	// machine, with no database. It must be absolute or start with ~/,
	// which is expanded, because the hook mode runs from each project's
	// directory. One process at a time may use it.
	StateDir string `yaml:"state_dir"`

	// LocalAgent names the agent in the local modes, such as the Claude
	// Code hook, where no API key tells agents apart.
	LocalAgent LocalAgent `yaml:"local_agent"`

	// StdioEnv names env vars passed on to the MCP server that
	// consequenced -stdio starts. It gets these and a few basics (PATH,
	// HOME and the like), nothing else from the agent's environment.
	StdioEnv []string `yaml:"stdio_env"`
	// StdioEnvFile is a file of KEY=value lines for that server, such as
	// its token. Only ConsequenceOS reads it, so the agent never sees the
	// token. It must be absolute or start with ~/, and readable by its
	// owner alone.
	StdioEnvFile string `yaml:"stdio_env_file"`
}

// LocalAgent is the agent and owner the local modes record calls under.
type LocalAgent struct {
	ID      string `yaml:"id"`
	OwnerID string `yaml:"owner_id"`
}

// The local agent's names when the config doesn't give them.
const (
	DefaultLocalAgentID    = "local"
	DefaultLocalAgentOwner = "local"
)

// Owner is an organisation whose agents use the proxy.
type Owner struct {
	ID        string   `yaml:"id"`
	Approvers []string `yaml:"approvers"` // email addresses
}

// Email configures approval emails. The SMTP URL holds a password, so it
// lives in an env var, e.g. smtp://user:pass@smtp.example.com:587.
type Email struct {
	SMTPURLEnv string `yaml:"smtp_url_env"`
	From       string `yaml:"from"`
	SMTPURL    string `yaml:"-"`
}

// Enabled reports whether approval emails are configured.
func (e Email) Enabled() bool { return e.SMTPURLEnv != "" }

// Receipts configures receipt signing. Both keys are secrets in env vars;
// generate them with `consequenced -genkeys`.
type Receipts struct {
	TTL           time.Duration `yaml:"ttl"` // how long a receipt is valid
	Ed25519KeyEnv string        `yaml:"ed25519_key_env"`
	MLDSA87KeyEnv string        `yaml:"mldsa87_key_env"`
	Ed25519Key    string        `yaml:"-"`
	MLDSA87Key    string        `yaml:"-"`
}

// Agent is a caller of the proxy. The API key itself never lives in the
// YAML file, only the name of the env var that holds it.
type Agent struct {
	ID        string `yaml:"id"`
	OwnerID   string `yaml:"owner_id"`
	APIKeyEnv string `yaml:"api_key_env"`
	APIKey    string `yaml:"-"` // filled from the env var; "-" means YAML never reads or writes it
}

// Receiver is a service that checks receipts with the verify endpoint
// before acting. Like agents, its key lives in an env var.
type Receiver struct {
	ID        string `yaml:"id"`
	APIKeyEnv string `yaml:"api_key_env"`
	APIKey    string `yaml:"-"`
}

// LookupEnv has the same signature as os.LookupEnv, so tests can pass a fake.
type LookupEnv func(key string) (string, bool)

// Load reads the config file at path and resolves secrets from the process env.
func Load(path string) (*Config, error) {
	return LoadEnv(path, os.LookupEnv)
}

// LoadEnv is Load with env vars read through lookupEnv, so a caller can
// layer its own values (such as a -listen flag) over the real environment.
func LoadEnv(path string, lookupEnv LookupEnv) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(data, lookupEnv)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes YAML, applies defaults, resolves secrets and validates.
func Parse(data []byte, lookupEnv LookupEnv) (*Config, error) {
	cfg, err := decode(data)
	if err != nil {
		return nil, err
	}

	if v, ok := lookupEnv(ListenEnv); ok && v != "" {
		cfg.Listen = v // the environment wins over the file
	}
	cfg.applyDefaults()
	if err := cfg.resolveSecrets(lookupEnv); err != nil {
		return nil, err
	}
	if err := cfg.resolveStateDir(lookupEnv); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadLocal reads and checks a config for the local modes. See ParseLocal.
func LoadLocal(path string, lookupEnv LookupEnv) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := ParseLocal(data, lookupEnv)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// ParseLocal is Parse for the local modes, such as the Claude Code hook.
// They need the policy, a state_dir to keep the audit log and limits
// between calls, and optionally local_agent. The HTTP server's settings,
// its secrets among them, are neither read nor checked.
func ParseLocal(data []byte, lookupEnv LookupEnv) (*Config, error) {
	cfg, err := decode(data)
	if err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if cfg.LocalAgent.ID == "" {
		cfg.LocalAgent.ID = DefaultLocalAgentID
	}
	if cfg.LocalAgent.OwnerID == "" {
		cfg.LocalAgent.OwnerID = DefaultLocalAgentOwner
	}
	if err := cfg.resolveStateDir(lookupEnv); err != nil {
		return nil, err
	}
	if cfg.StdioEnvFile != "" {
		if cfg.StdioEnvFile, err = absPath("stdio_env_file", cfg.StdioEnvFile, lookupEnv); err != nil {
			return nil, err
		}
	}
	if cfg.StateDir == "" {
		return nil, errors.New("state_dir is required here, e.g. state_dir: ~/.consequence, so the audit log and limits last from one call to the next")
	}
	if _, err := cfg.NewEngine(); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return cfg, nil
}

// decode reads the YAML strictly: unknown fields are errors.
func decode(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // reject typos like "rule:" instead of silently ignoring them
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// resolveStateDir expands a leading ~/ in state_dir and checks the result
// is absolute.
func (c *Config) resolveStateDir(lookupEnv LookupEnv) error {
	if c.StateDir == "" {
		return nil
	}
	if c.DatabaseURLEnv != "" {
		return errors.New("set database_url_env or state_dir, not both")
	}
	dir, err := absPath("state_dir", c.StateDir, lookupEnv)
	if err != nil {
		return err
	}
	c.StateDir = dir
	return nil
}

// absPath expands a leading ~/ in a path setting and checks the result is
// absolute. A bare ~ never arrives: YAML reads it as null.
func absPath(setting, p string, lookupEnv LookupEnv) (string, error) {
	dir := p
	if strings.HasPrefix(dir, "~/") {
		home, ok := lookupEnv("HOME")
		if !ok || home == "" {
			return "", fmt.Errorf("%s starts with ~ but $HOME is not set", setting)
		}
		dir = filepath.Join(home, strings.TrimPrefix(dir, "~"))
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("%s %q must be an absolute path or start with ~/", setting, p)
	}
	return filepath.Clean(dir), nil
}

// stdioBaseEnv are the env vars every server started by -stdio gets, when
// they're set: what programs need to run at all.
var stdioBaseEnv = []string{"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ"}

// StdioEnvironment returns the environment for the server -stdio starts:
// the basics and stdio_env's names from lookupEnv, then stdio_env_file's
// lines, which win over both.
func (c *Config) StdioEnvironment(lookupEnv LookupEnv) ([]string, error) {
	vars := map[string]string{}
	var order []string
	set := func(k, v string) {
		if _, ok := vars[k]; !ok {
			order = append(order, k)
		}
		vars[k] = v
	}
	for _, name := range append(append([]string(nil), stdioBaseEnv...), c.StdioEnv...) {
		if v, ok := lookupEnv(name); ok {
			set(name, v)
		}
	}
	if c.StdioEnvFile != "" {
		info, err := os.Stat(c.StdioEnvFile)
		if err != nil {
			return nil, fmt.Errorf("stdio_env_file: %w", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("stdio_env_file %s can be read by other users (mode %o); run chmod 600 on it", c.StdioEnvFile, info.Mode().Perm())
		}
		data, err := os.ReadFile(c.StdioEnvFile)
		if err != nil {
			return nil, fmt.Errorf("stdio_env_file: %w", err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			k = strings.TrimSpace(strings.TrimPrefix(k, "export "))
			if !ok || k == "" || strings.ContainsAny(k, " \t") {
				// The line may hold a secret, so it isn't repeated here.
				return nil, fmt.Errorf("stdio_env_file %s line %d must look like NAME=value", c.StdioEnvFile, i+1)
			}
			v = strings.TrimSpace(v)
			if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
				v = v[1 : len(v)-1]
			}
			set(k, v)
		}
	}
	env := make([]string, 0, len(order))
	for _, k := range order {
		env = append(env, k+"="+vars[k])
	}
	return env, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.ApprovalValidity == 0 {
		c.ApprovalValidity = DefaultApprovalValidity
	}
	if c.ApprovalTimeout == 0 {
		c.ApprovalTimeout = DefaultApprovalTimeout
	}
	if c.MaxPendingApprovals == 0 {
		c.MaxPendingApprovals = DefaultMaxPending
	}
	if c.DefaultAllowBelow == nil {
		n := policy.DefaultAllowBelow
		c.DefaultAllowBelow = &n
	}
	if c.Receipts.TTL == 0 {
		c.Receipts.TTL = DefaultReceiptTTL
	}
	if c.PublicURL == "" {
		c.PublicURL = defaultPublicURL(c.Listen)
	}
}

// defaultPublicURL turns a listen address into a URL for approval links.
// Listening on every interface (":8080", "0.0.0.0:8080", "[::]:8080") has
// no address a browser can use, so those links point at localhost.
func defaultPublicURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://" + listen // validate reports the bad address
	}
	if ip := net.ParseIP(host); host == "" || ip != nil && ip.IsUnspecified() {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func (c *Config) resolveSecrets(lookupEnv LookupEnv) error {
	// Each entry pairs a setting naming an env var with the field to fill.
	required := []struct {
		setting, env string
		dest         *string
	}{
		{"admin_token_env", c.AdminTokenEnv, &c.AdminToken},
		{"receipts.ed25519_key_env", c.Receipts.Ed25519KeyEnv, &c.Receipts.Ed25519Key},
		{"receipts.mldsa87_key_env", c.Receipts.MLDSA87KeyEnv, &c.Receipts.MLDSA87Key},
	}
	for _, r := range required {
		if r.env == "" {
			return fmt.Errorf("%s is required", r.setting)
		}
		value, ok := lookupEnv(r.env)
		if !ok || value == "" {
			return fmt.Errorf("env var %s (%s) is not set", r.env, r.setting)
		}
		*r.dest = value // write through the pointer into the Config field
	}
	if c.Email.Enabled() {
		value, ok := lookupEnv(c.Email.SMTPURLEnv)
		if !ok || value == "" {
			return fmt.Errorf("env var %s (email.smtp_url_env) is not set", c.Email.SMTPURLEnv)
		}
		c.Email.SMTPURL = value
	}
	if c.UpstreamAuthEnv != "" {
		value, ok := lookupEnv(c.UpstreamAuthEnv)
		if !ok || value == "" {
			return fmt.Errorf("env var %s (upstream_auth_env) is not set", c.UpstreamAuthEnv)
		}
		for _, r := range value {
			// A line break would let the token add headers of its own.
			if r <= ' ' || r == 0x7f {
				return fmt.Errorf("env var %s (upstream_auth_env) holds a space or control character; a token can't", c.UpstreamAuthEnv)
			}
		}
		c.UpstreamAuth = value
	}
	if c.DatabaseURLEnv != "" {
		value, ok := lookupEnv(c.DatabaseURLEnv)
		if !ok || value == "" {
			return fmt.Errorf("env var %s (database_url_env) is not set", c.DatabaseURLEnv)
		}
		c.DatabaseURL = value
	}

	// Index into the slice so we modify the element, not a copy of it.
	for i := range c.Agents {
		a := &c.Agents[i]
		if err := resolveKey("agent", a.ID, a.APIKeyEnv, &a.APIKey, lookupEnv); err != nil {
			return err
		}
	}
	for i := range c.Receivers {
		r := &c.Receivers[i]
		if err := resolveKey("receiver", r.ID, r.APIKeyEnv, &r.APIKey, lookupEnv); err != nil {
			return err
		}
	}
	return nil
}

// resolveKey reads the API key for an agent or receiver from its env var.
func resolveKey(kind, id, env string, dest *string, lookupEnv LookupEnv) error {
	if env == "" {
		return fmt.Errorf("%s %q: api_key_env is required", kind, id)
	}
	key, ok := lookupEnv(env)
	if !ok || key == "" {
		return fmt.Errorf("%s %q: env var %s is not set", kind, id, env)
	}
	*dest = key
	return nil
}

func (c *Config) validate() error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen %q must look like 127.0.0.1:8080 or 0.0.0.0:8080", c.Listen)
	}
	if err := validateUpstream(c.Upstream); err != nil {
		return err
	}
	if c.UpstreamAuth != "" && !private(c.Upstream) {
		return fmt.Errorf("upstream %q is plain http, so upstream_auth_env's token would cross the network unencrypted; use https, or a localhost upstream", c.Upstream)
	}
	if c.ApprovalValidity < 0 {
		return errors.New("approval_validity must be positive")
	}
	if c.ApprovalTimeout < 0 {
		return errors.New("approval_timeout must be positive")
	}
	if c.MaxPendingApprovals < 0 {
		return errors.New("max_pending_approvals must be positive")
	}
	if c.Receipts.TTL < 0 {
		return errors.New("receipts.ttl must be positive")
	}
	if err := validateAgents(c.Agents); err != nil {
		return err
	}
	if err := c.validateKeys(); err != nil {
		return err
	}
	if err := validateOwners(c.Owners, c.Agents); err != nil {
		return err
	}
	if c.Email.Enabled() {
		if addr, err := mail.ParseAddress(c.Email.From); err != nil || addr.Address != c.Email.From {
			return fmt.Errorf("email.from %q must be a plain email address", c.Email.From)
		}
	} else if c.Email.From != "" {
		return errors.New("email.from is set but email.smtp_url_env is not")
	}
	if err := validateOrigins(c.AllowedOrigins); err != nil {
		return err
	}
	if u, err := url.Parse(c.PublicURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("public_url %q must be an http(s) URL", c.PublicURL)
	}
	// Building the engine is the single source of truth for rule validation.
	if _, err := c.NewEngine(); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	return nil
}

// NewEngine builds the policy engine this config describes.
func (c *Config) NewEngine() (*policy.Engine, error) {
	var opts []policy.Option
	if c.DefaultAllowBelow != nil {
		opts = append(opts, policy.AllowBelow(*c.DefaultAllowBelow))
	}
	return policy.NewEngine(c.Rules, c.Tools, opts...)
}

func validateUpstream(raw string) error {
	if raw == "" {
		return errors.New("upstream is required")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("upstream %q must be an http(s) URL", raw)
	}
	return nil
}

// private reports whether a token sent to the upstream stays private on
// the way: the URL is https, or http to this machine.
func private(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateOrigins(origins []string) error {
	for _, o := range origins {
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Path != "" && u.Path != "/") {
			return fmt.Errorf("allowed_origins: %q must look like http://localhost:3000", o)
		}
	}
	return nil
}

func validateOwners(owners []Owner, agents []Agent) error {
	known := make(map[string]bool, len(owners))
	for _, o := range owners {
		if o.ID == "" {
			return errors.New("owners: every owner needs an id")
		}
		if known[o.ID] {
			return fmt.Errorf("owner %q: duplicate id", o.ID)
		}
		known[o.ID] = true
		if len(o.Approvers) == 0 {
			return fmt.Errorf("owner %q: list at least one approver", o.ID)
		}
		for _, a := range o.Approvers {
			if addr, err := mail.ParseAddress(a); err != nil || addr.Address != a {
				return fmt.Errorf("owner %q: approver %q must be a plain email address", o.ID, a)
			}
		}
	}
	for _, a := range agents {
		if !known[a.OwnerID] {
			return fmt.Errorf("agent %q: owner %q is not listed under owners", a.ID, a.OwnerID)
		}
	}
	return nil
}

// ApproversByOwner maps each owner ID to its approvers.
func (c *Config) ApproversByOwner() map[string][]string {
	m := make(map[string][]string, len(c.Owners))
	for _, o := range c.Owners {
		m[o.ID] = o.Approvers
	}
	return m
}

func validateAgents(agents []Agent) error {
	if len(agents) == 0 {
		return errors.New("at least one agent is required")
	}
	ids := make(map[string]bool)
	for _, a := range agents {
		if a.ID == "" || a.OwnerID == "" {
			return fmt.Errorf("agent %q: id and owner_id are required", a.ID)
		}
		if ids[a.ID] {
			return fmt.Errorf("agent %q: duplicate id", a.ID)
		}
		ids[a.ID] = true
	}
	return nil
}

// validateKeys checks receiver IDs and that no two credentials are the same
// secret, so an agent's key can't verify receipts or read the audit log.
func (c *Config) validateKeys() error {
	ids := make(map[string]bool)
	for _, r := range c.Receivers {
		if r.ID == "" {
			return errors.New("receivers: every receiver needs an id")
		}
		if ids[r.ID] {
			return fmt.Errorf("receiver %q: duplicate id", r.ID)
		}
		ids[r.ID] = true
	}
	// A receiver that verifies only offline needn't be listed, but when
	// receivers are listed, the upstream's must be one of them: a typo would
	// otherwise make every receipt refused with wrong_audience.
	if c.UpstreamReceiver != "" && len(c.Receivers) > 0 && !ids[c.UpstreamReceiver] {
		return fmt.Errorf("upstream_receiver %q is not one of the receivers", c.UpstreamReceiver)
	}

	// owner maps each secret to who uses it. Errors name env vars, never keys.
	owner := map[string]string{c.AdminToken: "the admin token"}
	claim := func(key, who, env string) error {
		if other, taken := owner[key]; taken {
			return fmt.Errorf("%s: API key in %s is already used by %s", who, env, other)
		}
		owner[key] = who
		return nil
	}
	for _, a := range c.Agents {
		if err := claim(a.APIKey, fmt.Sprintf("agent %q", a.ID), a.APIKeyEnv); err != nil {
			return err
		}
	}
	for _, r := range c.Receivers {
		if err := claim(r.APIKey, fmt.Sprintf("receiver %q", r.ID), r.APIKeyEnv); err != nil {
			return err
		}
	}
	return nil
}

// Warnings points out settings that are valid but weaker than they should
// be. consequenced -check prints them and the server logs them at startup.
func (c *Config) Warnings() []string {
	var w []string
	// A hosted upstream, reached with upstream_auth_env's token and with no
	// receivers listed, checks no receipts: the token is what keeps the
	// agent from going around ConsequenceOS. Receipt versions don't matter.
	hosted := c.UpstreamAuthEnv != "" && len(c.Receivers) == 0
	if c.UpstreamReceiver == "" && !hosted {
		w = append(w, "upstream_receiver is not set, so receipts are v0 and don't name their receiver: "+
			"any receiver with the same tool would accept them. Set it to the upstream's receiver ID.")
	}
	return w
}

// ReceiverKeys maps each receiver's API key to its ID.
func (c *Config) ReceiverKeys() map[string]string {
	m := make(map[string]string, len(c.Receivers))
	for _, r := range c.Receivers {
		m[r.APIKey] = r.ID
	}
	return m
}

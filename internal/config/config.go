// Package config loads consequence.yaml and resolves secrets from env vars.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/matutozi/consequence-os/internal/policy"
)

const (
	DefaultListen           = "127.0.0.1:8080"
	DefaultApprovalValidity = 10 * time.Minute
	DefaultReceiptTTL       = 5 * time.Minute
)

// Config is the whole of consequence.yaml.
type Config struct {
	Listen           string        `yaml:"listen"`
	Upstream         string        `yaml:"upstream"`
	ApprovalValidity time.Duration `yaml:"approval_validity"` // yaml.v3 parses strings like "10m"
	Agents           []Agent       `yaml:"agents"`
	Tools            policy.Levels `yaml:"tools"`
	Rules            []policy.Rule `yaml:"rules"`

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

	// DatabaseURLEnv names the env var holding a Postgres URL. When it's
	// empty, everything is kept in memory and lost on restart.
	DatabaseURLEnv string `yaml:"database_url_env"`
	DatabaseURL    string `yaml:"-"`
}

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

// LookupEnv has the same signature as os.LookupEnv, so tests can pass a fake.
type LookupEnv func(key string) (string, bool)

// Load reads the config file at path and resolves secrets from the process env.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(data, os.LookupEnv)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes YAML, applies defaults, resolves secrets and validates.
func Parse(data []byte, lookupEnv LookupEnv) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // reject typos like "rule:" instead of silently ignoring them
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.resolveSecrets(lookupEnv); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.ApprovalValidity == 0 {
		c.ApprovalValidity = DefaultApprovalValidity
	}
	if c.Receipts.TTL == 0 {
		c.Receipts.TTL = DefaultReceiptTTL
	}
	if c.PublicURL == "" {
		host := c.Listen
		if strings.HasPrefix(host, ":") { // ":8080" listens on every interface
			host = "localhost" + host
		}
		c.PublicURL = "http://" + host
	}
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
		if a.APIKeyEnv == "" {
			return fmt.Errorf("agent %q: api_key_env is required", a.ID)
		}
		key, ok := lookupEnv(a.APIKeyEnv)
		if !ok || key == "" {
			return fmt.Errorf("agent %q: env var %s is not set", a.ID, a.APIKeyEnv)
		}
		a.APIKey = key
	}
	return nil
}

func (c *Config) validate() error {
	if err := validateUpstream(c.Upstream); err != nil {
		return err
	}
	if c.ApprovalValidity < 0 {
		return errors.New("approval_validity must be positive")
	}
	if c.Receipts.TTL < 0 {
		return errors.New("receipts.ttl must be positive")
	}
	if err := validateAgents(c.Agents); err != nil {
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
	for _, a := range c.Agents {
		if a.APIKey == c.AdminToken {
			return fmt.Errorf("agent %q: API key in %s must differ from the admin token", a.ID, a.APIKeyEnv)
		}
	}
	if err := validateOrigins(c.AllowedOrigins); err != nil {
		return err
	}
	if u, err := url.Parse(c.PublicURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("public_url %q must be an http(s) URL", c.PublicURL)
	}
	// Building the engine is the single source of truth for rule validation.
	if _, err := policy.NewEngine(c.Rules, c.Tools); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	return nil
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
	keys := make(map[string]bool)
	for _, a := range agents {
		if a.ID == "" || a.OwnerID == "" {
			return fmt.Errorf("agent %q: id and owner_id are required", a.ID)
		}
		if ids[a.ID] {
			return fmt.Errorf("agent %q: duplicate id", a.ID)
		}
		if keys[a.APIKey] {
			// Don't print the key; name the env var instead.
			return fmt.Errorf("agent %q: API key in %s is already used by another agent", a.ID, a.APIKeyEnv)
		}
		ids[a.ID] = true
		keys[a.APIKey] = true
	}
	return nil
}

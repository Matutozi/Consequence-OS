package config

import (
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/policy"
)

// base holds the settings every valid config needs besides upstream and agents.
const base = `admin_token_env: ADMIN
receipts: { ed25519_key_env: ED_KEY, mldsa87_key_env: ML_KEY }
`

const validYAML = `
upstream: http://localhost:9090/mcp
` + base + `
owners:
  - id: acme
    approvers: [ada@acme.example, bo@acme.example]
agents:
  - id: support-bot
    owner_id: acme
    api_key_env: KEY_SUPPORT
tools:
  payments.refund: irreversible
  notes.read: read
rules:
  - name: small-refunds
    tool: payments.refund
    when: { arg: amount, op: lte, value: 50 }
    action: allow
  - name: big-refunds
    tool: payments.refund
    action: ask
  - name: trusted-small-po
    tool: purchase_order.confirm
    when:
      - { arg: amount, op: lt, value: 500 }
      - { arg: supplier, op: in, value: [Coleman Cables, Acme Steel] }
    action: allow
`

// fakeEnv returns a LookupEnv backed by a map instead of the real environment.
func fakeEnv(vars map[string]string) LookupEnv {
	return func(key string) (string, bool) {
		v, ok := vars[key]
		return v, ok
	}
}

// baseEnv holds values for the env vars named in base, plus any extras.
func baseEnv(extra map[string]string) LookupEnv {
	vars := map[string]string{"ADMIN": "admin-1", "ED_KEY": "ed-seed", "ML_KEY": "ml-seed"}
	for k, v := range extra {
		vars[k] = v
	}
	return fakeEnv(vars)
}

func TestParseValid(t *testing.T) {
	cfg, err := Parse([]byte(validYAML), baseEnv(map[string]string{"KEY_SUPPORT": "secret-1"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	checks := []struct {
		name      string
		got, want any
	}{
		{"default listen", cfg.Listen, DefaultListen},
		{"default validity", cfg.ApprovalValidity, 10 * time.Minute},
		{"default timeout", cfg.ApprovalTimeout, time.Hour},
		{"no receivers by default", len(cfg.Receivers), 0},
		{"default receipt ttl", cfg.Receipts.TTL, 5 * time.Minute},
		{"api key resolved", cfg.Agents[0].APIKey, "secret-1"},
		{"admin token resolved", cfg.AdminToken, "admin-1"},
		{"ed25519 key resolved", cfg.Receipts.Ed25519Key, "ed-seed"},
		{"ml-dsa key resolved", cfg.Receipts.MLDSA87Key, "ml-seed"},
		{"no database by default", cfg.DatabaseURL, ""},
		{"no email by default", cfg.Email.Enabled(), false},
		{"no origins by default", len(cfg.AllowedOrigins), 0},
		{"default public url", cfg.PublicURL, "http://127.0.0.1:8080"},
		{"owner", cfg.Agents[0].OwnerID, "acme"},
		{"approvers", strings.Join(cfg.ApproversByOwner()["acme"], ","), "ada@acme.example,bo@acme.example"},
		{"tool level", cfg.Tools["notes.read"], policy.LevelRead},
		{"rule count", len(cfg.Rules), 3},
		{"condition count", len(cfg.Rules[0].When), 1},
		{"condition op", cfg.Rules[0].When[0].Op, policy.OpLte},
		{"condition value", cfg.Rules[0].When[0].Value, 50},
		{"no condition", cfg.Rules[1].When == nil, true},
		{"list conditions", len(cfg.Rules[2].When), 2},
		{"in list value", len(cfg.Rules[2].When[1].Value.([]any)), 2},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("got %v (%T), want %v (%T)", c.got, c.got, c.want, c.want)
			}
		})
	}
}

func TestParseOverrides(t *testing.T) {
	yml := validYAML + "listen: \":9999\"\napproval_validity: 90s\napproval_timeout: 2h\ndatabase_url_env: DB\n" +
		"email: { smtp_url_env: SMTP, from: approvals@acme.example }\n" +
		"receivers: [{ id: payments-api, api_key_env: RECV }]\n"
	cfg, err := Parse([]byte(yml), baseEnv(map[string]string{"KEY_SUPPORT": "k", "DB": "postgres://x", "SMTP": "smtp://mailpit:1025", "RECV": "r"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Listen != ":9999" || cfg.ApprovalValidity != 90*time.Second || cfg.PublicURL != "http://localhost:9999" || cfg.DatabaseURL != "postgres://x" {
		t.Errorf("got listen=%q validity=%v public=%q db=%q", cfg.Listen, cfg.ApprovalValidity, cfg.PublicURL, cfg.DatabaseURL)
	}
	if !cfg.Email.Enabled() || cfg.Email.SMTPURL != "smtp://mailpit:1025" || cfg.Email.From != "approvals@acme.example" {
		t.Errorf("email = %+v", cfg.Email)
	}
	if cfg.ApprovalTimeout != 2*time.Hour {
		t.Errorf("approval_timeout = %v", cfg.ApprovalTimeout)
	}
	if got := cfg.ReceiverKeys(); len(got) != 1 || got["r"] != "payments-api" {
		t.Errorf("receiver keys = %v", got)
	}
}

func TestParseErrors(t *testing.T) {
	env := baseEnv(map[string]string{"KEY_A": "a", "KEY_B": "b", "KEY_DUP": "a", "RECV": "r"})
	upstream := "upstream: http://localhost:9090/mcp\n"
	owners := "owners: [{ id: o, approvers: [ada@o.example] }]\n"
	agentA := "agents:\n  - { id: a, owner_id: o, api_key_env: KEY_A }\n"
	ok := upstream + base + owners // everything but agents

	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"empty file", "", "empty"},
		{"unknown field", ok + agentA + "rule: []\n", "field rule not found"},
		{"missing upstream", base + owners + agentA, "upstream is required"},
		{"bad upstream", "upstream: ftp://x\n" + base + owners + agentA, "http(s) URL"},
		{"missing admin token env", upstream + "receipts: { ed25519_key_env: ED_KEY, mldsa87_key_env: ML_KEY }\n" + owners + agentA, "admin_token_env is required"},
		{"admin token not set", strings.Replace(ok, "ADMIN", "NOPE", 1) + agentA, "NOPE (admin_token_env) is not set"},
		{"missing receipt key env", upstream + "admin_token_env: ADMIN\n" + owners + agentA, "receipts.ed25519_key_env is required"},
		{"receipt key not set", strings.Replace(ok, "ML_KEY", "NOPE", 1) + agentA, "NOPE (receipts.mldsa87_key_env) is not set"},
		{"database env not set", ok + agentA + "database_url_env: NOPE\n", "NOPE (database_url_env) is not set"},
		{"smtp env not set", ok + agentA + "email: { smtp_url_env: NOPE, from: a@o.example }\n", "NOPE (email.smtp_url_env) is not set"},
		{"bad email from", ok + agentA + "email: { smtp_url_env: ADMIN, from: approvals }\n", "email.from"},
		{"email from without smtp", ok + agentA + "email: { from: a@o.example }\n", "smtp_url_env is not"},
		{"no agents", ok, "at least one agent"},
		{"missing env name", ok + "agents:\n  - { id: a, owner_id: o }\n", "api_key_env is required"},
		{"env not set", ok + "agents:\n  - { id: a, owner_id: o, api_key_env: NOPE }\n", "NOPE is not set"},
		{"missing owner", ok + "agents:\n  - { id: a, api_key_env: KEY_A }\n", "owner_id are required"},
		{"owner not listed", ok + "agents:\n  - { id: a, owner_id: ghost, api_key_env: KEY_A }\n", `owner "ghost" is not listed`},
		{"owner without approvers", upstream + base + "owners: [{ id: o, approvers: [] }]\n" + agentA, "at least one approver"},
		{"approver not an email", upstream + base + "owners: [{ id: o, approvers: [ada] }]\n" + agentA, "plain email"},
		{"approver with display name", upstream + base + `owners: [{ id: o, approvers: ["Ada <ada@o.example>"] }]` + "\n" + agentA, "plain email"},
		{"duplicate owner", upstream + base + "owners: [{ id: o, approvers: [a@o.example] }, { id: o, approvers: [b@o.example] }]\n" + agentA, "duplicate id"},
		{"duplicate id", ok + agentA + "  - { id: a, owner_id: o, api_key_env: KEY_B }\n", "duplicate id"},
		{"duplicate key", ok + agentA + "  - { id: b, owner_id: o, api_key_env: KEY_DUP }\n", "already used"},
		{"agent key equals admin token", ok + "agents:\n  - { id: a, owner_id: o, api_key_env: ADMIN }\n", "already used by the admin token"},
		{"negative timeout", ok + agentA + "approval_timeout: -1m\n", "approval_timeout must be positive"},
		{"receiver env not set", ok + agentA + "receivers: [{ id: r, api_key_env: NOPE }]\n", `receiver "r": env var NOPE is not set`},
		{"receiver without env", ok + agentA + "receivers: [{ id: r }]\n", `receiver "r": api_key_env is required`},
		{"receiver without id", ok + agentA + "receivers: [{ api_key_env: RECV }]\n", "every receiver needs an id"},
		{"duplicate receiver", ok + agentA + "receivers: [{ id: r, api_key_env: RECV }, { id: r, api_key_env: KEY_B }]\n", `receiver "r": duplicate id`},
		{"receiver key equals agent key", ok + agentA + "receivers: [{ id: r, api_key_env: KEY_DUP }]\n", `receiver "r": API key in KEY_DUP is already used by agent "a"`},
		{"bad duration", ok + agentA + "approval_validity: soon\n", "parse config"},
		{"bad level", ok + agentA + "tools: { x: scary }\n", "unknown level"},
		{"bad rule", ok + agentA + "rules:\n  - { name: r, tool: x, action: maybe }\n", "unknown action"},
		{"typo inside when", ok + agentA + "rules:\n  - { name: r, tool: x, action: allow, when: { arg: a, op: eq, vlaue: 1 } }\n", "unknown condition field"},
		{"bad in list", ok + agentA + "rules:\n  - { name: r, tool: x, action: allow, when: { arg: a, op: in, value: USD } }\n", "non-empty list"},
		{"bad origin", ok + agentA + "allowed_origins: [localhost]\n", "allowed_origins"},
		{"bad public url", ok + agentA + "public_url: approvals.example\n", "public_url"},
		{"origin with path", ok + agentA + "allowed_origins: [\"http://localhost:3000/app\"]\n", "allowed_origins"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml), env)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestErrorsNeverContainSecrets(t *testing.T) {
	yml := "upstream: http://x\n" + base + "owners: [{ id: o, approvers: [a@o.example] }]\n" +
		"agents:\n  - { id: a, owner_id: o, api_key_env: K1 }\n  - { id: b, owner_id: o, api_key_env: K2 }\n"
	_, err := Parse([]byte(yml), baseEnv(map[string]string{"K1": "super-secret", "K2": "super-secret"}))
	if err == nil {
		t.Fatal("expected duplicate key error")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Errorf("error leaks the API key: %v", err)
	}
}

func TestParseLimitsAndSchedules(t *testing.T) {
	ok := "upstream: http://x\n" + base + "owners: [{ id: o, approvers: [a@o.example] }]\n" +
		"agents:\n  - { id: a, owner_id: o, api_key_env: K }\n"
	env := baseEnv(map[string]string{"K": "k"})

	cfg, err := Parse([]byte(ok+`rules:
  - name: daily-cap
    tool: payments.refund
    limit: { sum: amount, max: 500, per: 24h }
    outside: { days: [sat, sun], hours: "09:00-17:00", timezone: Africa/Lagos }
    action: ask
`), env)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := cfg.Rules[0]
	if r.Limit == nil || r.Limit.Per != 24*time.Hour || r.Limit.Sum != "amount" || r.Limit.Max != 500 {
		t.Errorf("limit = %+v", r.Limit)
	}
	if r.Outside == nil || r.Outside.Timezone != "Africa/Lagos" || len(r.Outside.Days) != 2 {
		t.Errorf("outside = %+v", r.Outside)
	}

	bad := []struct{ name, rule, wantErr string }{
		{"typo in limit", "limit: { maxx: 5, per: 1h }", "field maxx not found"},
		{"typo in schedule", "during: { hour: \"09:00-17:00\", timezone: UTC }", "field hour not found"},
		{"bad duration", "limit: { max: 5, per: soon }", "parse config"},
		{"bad timezone", "during: { timezone: Nowhere/Land }", `rule 1 ("r"): during: unknown timezone`},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			yml := ok + "rules:\n  - { name: r, tool: x, action: ask, " + tt.rule + " }\n"
			if _, err := Parse([]byte(yml), env); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

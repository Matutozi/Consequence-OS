package config

import (
	"os"
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
		{"default pending cap", cfg.MaxPendingApprovals, DefaultMaxPending},
		{"default allow below", *cfg.DefaultAllowBelow, policy.DefaultAllowBelow},
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
	yml := validYAML + "listen: \":9999\"\napproval_validity: 90s\napproval_timeout: 2h\nmax_pending_approvals: 5\ndefault_allow_below: 0\ndatabase_url_env: DB\n" +
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
	if cfg.DefaultAllowBelow == nil || *cfg.DefaultAllowBelow != 0 {
		t.Errorf("default_allow_below: 0 must stay 0, got %v", cfg.DefaultAllowBelow)
	}
	if cfg.MaxPendingApprovals != 5 {
		t.Errorf("max_pending_approvals = %d", cfg.MaxPendingApprovals)
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
		{"negative pending cap", ok + agentA + "max_pending_approvals: -1\n", "max_pending_approvals must be positive"},
		{"allow below out of range", ok + agentA + "default_allow_below: 101\n", "default_allow_below must be from 0 to 100"},
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

// TestShippedConfigsLoad keeps the example configs in the repo valid.
func TestShippedConfigsLoad(t *testing.T) {
	env := fakeEnv(map[string]string{
		"CONSEQUENCE_ADMIN_TOKEN": "a", "CONSEQUENCE_SIGNING_KEY_ED25519": "e", "CONSEQUENCE_SIGNING_KEY_MLDSA87": "m",
		"CONSEQUENCE_KEY_SUPPORT_BOT": "s", "CONSEQUENCE_KEY_RECEIVER_PAYMENTS": "r",
		"CONSEQUENCE_DATABASE_URL": "postgres://x", "CONSEQUENCE_SMTP_URL": "smtp://mailpit:1025",
	})
	for _, path := range []string{"../../consequence.yaml", "../../deploy/consequence.docker.yaml", "../../examples/policies.yaml"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(data, env); err != nil {
				t.Errorf("%s: %v", path, err)
			}
		})
	}
}

func TestListenOverrideAndPublicURL(t *testing.T) {
	yml := validYAML + "listen: \"127.0.0.1:8080\"\n"
	tests := []struct {
		name, envListen, wantListen, wantPublic string
	}{
		{"file value", "", "127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"env wins over the file", "0.0.0.0:9000", "0.0.0.0:9000", "http://localhost:9000"},
		{"all interfaces, no host", ":7000", ":7000", "http://localhost:7000"},
		{"all IPv6 interfaces", "[::]:7000", "[::]:7000", "http://localhost:7000"},
		{"a specific IPv6 address", "[::1]:7000", "[::1]:7000", "http://[::1]:7000"},
		{"a host name", "proxy.internal:7000", "proxy.internal:7000", "http://proxy.internal:7000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := baseEnv(map[string]string{"KEY_SUPPORT": "k", ListenEnv: tt.envListen})
			cfg, err := Parse([]byte(yml), env)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Listen != tt.wantListen || cfg.PublicURL != tt.wantPublic {
				t.Errorf("listen=%q public=%q, want %q and %q", cfg.Listen, cfg.PublicURL, tt.wantListen, tt.wantPublic)
			}
		})
	}

	// An explicit public_url is never replaced.
	cfg, _ := Parse([]byte(yml+"public_url: https://approvals.acme.example\n"), baseEnv(map[string]string{"KEY_SUPPORT": "k", ListenEnv: "0.0.0.0:8080"}))
	if cfg.PublicURL != "https://approvals.acme.example" {
		t.Errorf("public_url = %q", cfg.PublicURL)
	}

	if _, err := Parse([]byte(validYAML), baseEnv(map[string]string{"KEY_SUPPORT": "k", ListenEnv: "8080"})); err == nil ||
		!strings.Contains(err.Error(), `listen "8080" must look like`) {
		t.Errorf("a listen address without a port: err = %v", err)
	}
}

func TestUpstreamReceiver(t *testing.T) {
	ok := "upstream: http://x\n" + base + "owners: [{ id: o, approvers: [a@o.example] }]\n" +
		"agents:\n  - { id: a, owner_id: o, api_key_env: K }\n"
	env := baseEnv(map[string]string{"K": "k", "R": "r"})
	listed := "receivers: [{ id: payments-api, api_key_env: R }]\n"
	tests := []struct {
		name, yaml, wantErr string
		wantWarning         bool
	}{
		{"names a listed receiver", ok + listed + "upstream_receiver: payments-api\n", "", false},
		{"names an unlisted receiver", ok + listed + "upstream_receiver: payments-apy\n", `upstream_receiver "payments-apy" is not one of the receivers`, false},
		{"offline-only receiver needn't be listed", ok + "upstream_receiver: payments-api\n", "", false},
		{"unset warns", ok + listed, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tt.yaml), env)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			warned := strings.Contains(strings.Join(cfg.Warnings(), "\n"), "upstream_receiver is not set")
			if warned != tt.wantWarning {
				t.Errorf("warned = %v, want %v", warned, tt.wantWarning)
			}
		})
	}
}

func TestStateDir(t *testing.T) {
	tests := []struct {
		name, dir, home, want, wantErr string
	}{
		{"absolute", "/var/lib/consequence", "", "/var/lib/consequence", ""},
		{"cleaned", "/var/lib/consequence/../c/", "", "/var/lib/c", ""},
		{"home", "~/.consequence", "/home/ada", "/home/ada/.consequence", ""},
		{"relative", ".consequence", "", "", `state_dir ".consequence" must be an absolute path or start with ~/`},
		{"another user's home", "~bo/.consequence", "/home/ada", "", "must be an absolute path"},
		{"no home", "~/.consequence", "", "", "$HOME is not set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := map[string]string{"KEY_SUPPORT": "k"}
			if tt.home != "" {
				env["HOME"] = tt.home
			}
			cfg, err := Parse([]byte(validYAML+"state_dir: "+tt.dir+"\n"), baseEnv(env))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.StateDir != tt.want {
				t.Errorf("state_dir = %q, want %q", cfg.StateDir, tt.want)
			}
		})
	}

	_, err := Parse([]byte(validYAML+"state_dir: /x\ndatabase_url_env: DB\n"), baseEnv(map[string]string{"KEY_SUPPORT": "k", "DB": "postgres://x"}))
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("both stores: err = %v", err)
	}
}

func TestParseLocal(t *testing.T) {
	env := fakeEnv(map[string]string{"HOME": "/home/ada"})
	policyOnly := "state_dir: ~/.consequence\ntools: { Bash: irreversible }\nrules:\n  - { name: shell, tool: Bash, action: ask }\n"

	cfg, err := ParseLocal([]byte(policyOnly), env)
	if err != nil {
		t.Fatalf("a policy and a state_dir should be enough: %v", err)
	}
	if cfg.StateDir != "/home/ada/.consequence" || cfg.LocalAgent.ID != DefaultLocalAgentID || cfg.LocalAgent.OwnerID != DefaultLocalAgentOwner {
		t.Errorf("got state_dir %q, local agent %+v", cfg.StateDir, cfg.LocalAgent)
	}
	cfg, err = ParseLocal([]byte(policyOnly+"local_agent: { id: claude-code, owner_id: ada }\n"), env)
	if err != nil || cfg.LocalAgent != (LocalAgent{ID: "claude-code", OwnerID: "ada"}) {
		t.Errorf("local_agent = %+v, %v", cfg.LocalAgent, err)
	}
	// The server's config works too: its secrets aren't needed, so unset env vars don't matter.
	if _, err := ParseLocal([]byte(validYAML+"state_dir: /srv/state\n"), env); err != nil {
		t.Errorf("server config with a state_dir: %v", err)
	}

	for name, tt := range map[string]struct{ yaml, want string }{
		"no state_dir":  {"rules: []\n", "state_dir is required"},
		"a bad rule":    {"state_dir: /x\nrules:\n  - { name: r, tool: Bash, action: maybe }\n", "policy:"},
		"unknown field": {"state_dir: /x\nrule: []\n", "field rule not found"},
		"empty":         {"", "empty"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseLocal([]byte(tt.yaml), env); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestUpstreamAuth(t *testing.T) {
	withUpstream := func(u string) string {
		return strings.Replace(validYAML, "upstream: http://localhost:9090/mcp", "upstream: "+u, 1) + "upstream_auth_env: UP_TOKEN\n"
	}
	if !strings.Contains(validYAML, "upstream: http://localhost:9090/mcp") {
		t.Fatal("validYAML's upstream changed; update this test")
	}
	tests := []struct {
		name, upstream, token, wantErr string
	}{
		{"https", "https://api.githubcopilot.com/mcp/", "ghp_abc", ""},
		{"localhost", "http://localhost:9090/mcp", "t", ""},
		{"loopback", "http://127.0.0.1:9090/mcp", "t", ""},
		{"loopback v6", "http://[::1]:9090/mcp", "t", ""},
		{"plain http elsewhere", "http://tools.internal:9090/mcp", "t", "is plain http"},
		{"looks local but isn't", "http://localhost.evil.example/mcp", "t", "is plain http"},
		{"not set", "https://x.example/mcp", "", "UP_TOKEN (upstream_auth_env) is not set"},
		{"a line break", "https://x.example/mcp", "t\r\nX-Evil: 1", "space or control character"},
		{"a space", "https://x.example/mcp", "Bearer t", "space or control character"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := map[string]string{"KEY_SUPPORT": "k"}
			if tt.token != "" {
				env["UP_TOKEN"] = tt.token
			}
			cfg, err := Parse([]byte(withUpstream(tt.upstream)), baseEnv(env))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				if strings.Contains(err.Error(), "X-Evil") {
					t.Error("the error repeats the token")
				}
				return
			}
			if err != nil || cfg.UpstreamAuth != tt.token {
				t.Errorf("UpstreamAuth = %q, err %v", cfg.UpstreamAuth, err)
			}
		})
	}
}

func TestNoReceiptWarningForAHostedUpstream(t *testing.T) {
	yml := strings.Replace(validYAML, "upstream: http://localhost:9090/mcp", "upstream: https://api.githubcopilot.com/mcp/", 1) + "upstream_auth_env: UP_TOKEN\n"
	cfg, err := Parse([]byte(yml), baseEnv(map[string]string{"KEY_SUPPORT": "k", "UP_TOKEN": "ghp_x"}))
	if err != nil {
		t.Fatal(err)
	}
	if w := cfg.Warnings(); len(w) != 0 {
		t.Errorf("warnings for a hosted upstream: %q", w)
	}
	// With receivers listed, ConsequenceOS's receipts do matter again.
	cfg, err = Parse([]byte(yml+"receivers: [{ id: tools, api_key_env: RECV }]\n"), baseEnv(map[string]string{"KEY_SUPPORT": "k", "UP_TOKEN": "ghp_x", "RECV": "r"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings()) != 1 {
		t.Errorf("want the upstream_receiver warning back with receivers listed: %q", cfg.Warnings())
	}
}

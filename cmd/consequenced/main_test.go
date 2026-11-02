package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/receipt"
)

const testConfig = `
upstream: http://127.0.0.1:9090/mcp
admin_token_env: TEST_CONSEQUENCED_ADMIN
receipts: { ed25519_key_env: TEST_CONSEQUENCED_ED, mldsa87_key_env: TEST_CONSEQUENCED_ML }
owners: [{ id: acme, approvers: [ada@acme.example] }]
agents:
  - { id: support-bot, owner_id: acme, api_key_env: TEST_CONSEQUENCED_KEY }
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
  - name: small-po-trusted-supplier
    tool: odoo.purchase_order.confirm
    when:
      - { arg: amount, op: lt, value: 500 }
      - { arg: supplier, op: in, value: [Coleman Cables, Acme Steel] }
    action: allow
`

func TestRun(t *testing.T) {
	// t.Setenv restores the variable when the test ends.
	path := writeTestConfig(t, "")

	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr string
	}{
		{"summary", []string{"-config", path, "-check"}, "config OK", ""},
		{"summary never prints the key", []string{"-config", path, "-check"}, "key from $TEST_CONSEQUENCED_KEY", ""},
		{"summary names the admin env var", []string{"-config", path, "-check"}, "admin token from:  $TEST_CONSEQUENCED_ADMIN", ""},
		{"summary lists approvers", []string{"-config", path, "-check"}, "acme, approvers: ada@acme.example", ""},
		{"summary shows storage", []string{"-config", path, "-check"}, "in memory", ""},
		{"genkeys", []string{"-genkeys"}, "CONSEQUENCE_SIGNING_KEY_MLDSA87=", ""},
		{"small refund", []string{"-config", path, "-tool", "payments.refund", "-args", `{"amount":20}`}, "action=allow rule=small-refunds", ""},
		{"big refund", []string{"-config", path, "-tool", "payments.refund", "-args", `{"amount":5000}`}, "action=ask rule=big-refunds", ""},
		{"read tool", []string{"-config", path, "-tool", "notes.read"}, "level=read action=allow rule=default", ""},
		{"summary joins conditions", []string{"-config", path, "-check"}, "when amount lt 500 and supplier in [Coleman Cables, Acme Steel]", ""},
		{"small po from trusted supplier", []string{"-config", path, "-tool", "odoo.purchase_order.confirm", "-args", `{"amount":120,"supplier":"Coleman Cables"}`}, "action=allow rule=small-po-trusted-supplier", ""},
		{"small po from unknown supplier", []string{"-config", path, "-tool", "odoo.purchase_order.confirm", "-args", `{"amount":120,"supplier":"Someone Else"}`}, "action=ask rule=default", ""},
		{"bad args", []string{"-config", path, "-tool", "notes.read", "-args", "[1]"}, "", "JSON object"},
		{"missing config", []string{"-config", "/does/not/exist.yaml"}, "", "read config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(context.Background(), tt.args, &out)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if !strings.Contains(out.String(), tt.want) {
				t.Errorf("output %q does not contain %q", out.String(), tt.want)
			}
			if strings.Contains(out.String(), "dev-key") || strings.Contains(out.String(), "dev-admin") {
				t.Error("output leaks a secret")
			}
		})
	}
}

// writeTestConfig writes testConfig plus extra YAML to a temp file and sets
// the env vars it refers to. t.Setenv restores them when the test ends.
func writeTestConfig(t *testing.T, extra string) string {
	t.Helper()
	t.Setenv("TEST_CONSEQUENCED_KEY", "dev-key")
	t.Setenv("TEST_CONSEQUENCED_ADMIN", "dev-admin")
	ed, ml, err := receipt.GenerateSeeds()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_CONSEQUENCED_ED", ed)
	t.Setenv("TEST_CONSEQUENCED_ML", ml)
	path := filepath.Join(t.TempDir(), "consequence.yaml")
	if err := os.WriteFile(path, []byte(testConfig+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServeStopsOnCancel(t *testing.T) {
	path := writeTestConfig(t, "listen: 127.0.0.1:0\n") // port 0: the OS picks a free port
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-config", path}, &bytes.Buffer{}) }()

	time.Sleep(100 * time.Millisecond) // let the server start
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v, want nil after a clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
}

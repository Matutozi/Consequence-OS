package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	neturl "net/url" // renamed so it doesn't clash with the url variables below
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// The same tests run against every Store implementation, so the in-memory
// store and Postgres can't drift apart. Postgres runs only when
// CONSEQUENCE_TEST_DATABASE_URL points at a server where we may create
// databases, e.g. postgres://postgres:test@127.0.0.1:55432/postgres.
func stores(t *testing.T) map[string]func(t *testing.T) Store {
	return map[string]func(t *testing.T) Store{
		"memory":   func(*testing.T) Store { return NewMemory() },
		"postgres": newTestPostgres,
	}
}

// newTestPostgres creates a fresh database for one test and drops it after.
func newTestPostgres(t *testing.T) Store {
	t.Helper()
	url := os.Getenv("CONSEQUENCE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set CONSEQUENCE_TEST_DATABASE_URL to run Postgres tests")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "consequence_test_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}

	// Point the URL at the new database. (pgx's ConnString() would return
	// the original string, ignoring any change to the parsed config.)
	u, err := neturl.Parse(url)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	st, err := OpenPostgres(ctx, u.String())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		st.Close()
		_, _ = admin.Exec(ctx, "DROP DATABASE "+name)
		admin.Close(ctx)
	})
	return st
}

// forEachStore runs test once per store implementation, as a named subtest.
func forEachStore(t *testing.T, test func(t *testing.T, st Store)) {
	for name, open := range stores(t) {
		t.Run(name, func(t *testing.T) { test(t, open(t)) })
	}
}

var at = time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

func TestAudit(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		seed := []audit.Entry{
			{Time: at, AgentID: "bot-a", OwnerID: "o", Tool: "payments.refund", Decision: policy.ActionAllow, Outcome: audit.OutcomeForwarded, ReceiptID: "rcpt_1"},
			{Time: at.Add(1 * time.Minute), AgentID: "bot-a", OwnerID: "o", Tool: "payments.refund", Decision: policy.ActionAsk, Outcome: audit.OutcomeHeld, ApprovalID: "apr_1"},
			{Time: at.Add(2 * time.Minute), AgentID: "bot-b", OwnerID: "o", Tool: "db.delete_users", Decision: policy.ActionDeny, Outcome: audit.OutcomeBlocked},
			{Time: at.Add(3 * time.Minute), AgentID: "bot-b", OwnerID: "o", Tool: "notes.read", Decision: policy.ActionAllow, Outcome: audit.OutcomeForwarded},
		}
		for _, e := range seed {
			saved, err := st.AppendAudit(ctx, e)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(saved.ID, "aud_") || len(saved.ID) != 20 {
				t.Errorf("unexpected ID %q", saved.ID)
			}
		}

		tests := []struct {
			name      string
			filter    audit.Filter
			wantTools []string // in the order returned
		}{
			{"all, newest first", audit.Filter{}, []string{"notes.read", "db.delete_users", "payments.refund", "payments.refund"}},
			{"by agent", audit.Filter{AgentID: "bot-b"}, []string{"notes.read", "db.delete_users"}},
			{"by tool", audit.Filter{Tool: "payments.refund"}, []string{"payments.refund", "payments.refund"}},
			{"by decision", audit.Filter{Decision: policy.ActionAllow}, []string{"notes.read", "payments.refund"}},
			{"since is inclusive", audit.Filter{Since: at.Add(2 * time.Minute)}, []string{"notes.read", "db.delete_users"}},
			{"until is exclusive", audit.Filter{Until: at.Add(1 * time.Minute)}, []string{"payments.refund"}},
			{"combined", audit.Filter{AgentID: "bot-a", Decision: policy.ActionAsk}, []string{"payments.refund"}},
			{"limit", audit.Filter{Limit: 1}, []string{"notes.read"}},
			{"no match", audit.Filter{AgentID: "nobody"}, nil},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := st.ListAudit(ctx, tt.filter)
				if err != nil {
					t.Fatal(err)
				}
				var tools []string
				for _, e := range got {
					tools = append(tools, e.Tool)
				}
				if fmt.Sprint(tools) != fmt.Sprint(tt.wantTools) {
					t.Errorf("got %v, want %v", tools, tt.wantTools)
				}
			})
		}

		// Every field survives the round trip.
		oldest, _ := st.ListAudit(ctx, audit.Filter{Until: at.Add(time.Second)})
		want := seed[0]
		want.ID = oldest[0].ID
		if oldest[0] != want {
			t.Errorf("round trip:\n got  %+v\n want %+v", oldest[0], want)
		}
	})
}

func TestAuditKeepsGivenID(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		saved, err := st.AppendAudit(context.Background(), audit.Entry{ID: "aud_fixed", Time: at, Outcome: audit.OutcomeHeld})
		if err != nil || saved.ID != "aud_fixed" {
			t.Errorf("ID = %q, err %v", saved.ID, err)
		}
	})
}

func TestConcurrentAppends(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		var wg sync.WaitGroup // waits for a group of goroutines to finish
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() { // "go" runs the function concurrently
				defer wg.Done()
				_, _ = st.AppendAudit(context.Background(), audit.Entry{Time: at, Tool: "x", Outcome: audit.OutcomeHeld})
			}()
		}
		wg.Wait()
		got, _ := st.ListAudit(context.Background(), audit.Filter{Limit: audit.MaxLimit})
		if len(got) != 50 {
			t.Errorf("got %d entries, want 50", len(got))
		}
	})
}

func pendingApproval(id, hash string) approval.Approval {
	return approval.Approval{
		ID: id, AgentID: "bot", OwnerID: "acme", Tool: "payments.refund", ParamsHash: hash,
		Summary: "payments.refund with amount", Arguments: []byte(`{"amount":5000}`),
		Level: policy.LevelIrreversible, Rule: "big-refunds", Status: approval.StatusPending, CreatedAt: at,
		Tokens: []approval.ApproverToken{
			{Approver: "ada@acme.example", Hash: sha256.Sum256([]byte("ada-secret"))},
			{Approver: "bo@acme.example", Hash: sha256.Sum256([]byte("bo-secret"))},
		},
	}
}

func TestApprovals(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		for _, a := range []approval.Approval{pendingApproval("apr_1", "h1"), pendingApproval("apr_2", "h1"), pendingApproval("apr_3", "h2")} {
			if err := st.CreateApproval(ctx, a); err != nil {
				t.Fatal(err)
			}
		}

		tests := []struct {
			name    string
			run     func() (approval.Approval, error)
			wantID  string
			wantErr error
		}{
			{"get", func() (approval.Approval, error) { return st.GetApproval(ctx, "apr_3") }, "apr_3", nil},
			{"get missing", func() (approval.Approval, error) { return st.GetApproval(ctx, "apr_9") }, "", approval.ErrNotFound},
			{"latest wins", func() (approval.Approval, error) { return st.FindLatestApproval(ctx, "bot", "payments.refund", "h1") }, "apr_2", nil},
			{"other agent", func() (approval.Approval, error) { return st.FindLatestApproval(ctx, "other", "payments.refund", "h1") }, "", approval.ErrNotFound},
			{"use before approval", func() (approval.Approval, error) { return st.UseApproval(ctx, "apr_2", at) }, "", approval.ErrNotUsable},
			{"use missing", func() (approval.Approval, error) { return st.UseApproval(ctx, "apr_9", at) }, "", approval.ErrNotFound},
			{"approve", func() (approval.Approval, error) {
				return st.DecideApproval(ctx, "apr_2", approval.StatusApproved, "ada@acme.example", at, at.Add(time.Minute))
			}, "apr_2", nil},
			{"decide twice", func() (approval.Approval, error) {
				return st.DecideApproval(ctx, "apr_2", approval.StatusRejected, "bo@acme.example", at, time.Time{})
			}, "", approval.ErrNotPending},
			{"decide missing", func() (approval.Approval, error) {
				return st.DecideApproval(ctx, "apr_9", approval.StatusApproved, "ada@acme.example", at, at)
			}, "", approval.ErrNotFound},
			{"use after window", func() (approval.Approval, error) { return st.UseApproval(ctx, "apr_2", at.Add(time.Minute)) }, "", approval.ErrNotUsable},
			{"use in window", func() (approval.Approval, error) { return st.UseApproval(ctx, "apr_2", at.Add(time.Second)) }, "apr_2", nil},
			{"use twice", func() (approval.Approval, error) { return st.UseApproval(ctx, "apr_2", at.Add(2*time.Second)) }, "", approval.ErrNotUsable},
			{"reject", func() (approval.Approval, error) {
				return st.DecideApproval(ctx, "apr_3", approval.StatusRejected, "bo@acme.example", at, time.Time{})
			}, "apr_3", nil},
		}
		// These steps build on each other, so they run in order on one store.
		for _, tt := range tests {
			got, err := tt.run()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("%s: err = %v, want %v", tt.name, err, tt.wantErr)
			}
			if got.ID != tt.wantID {
				t.Errorf("%s: id = %q, want %q", tt.name, got.ID, tt.wantID)
			}
		}

		used, _ := st.GetApproval(ctx, "apr_2")
		if used.Status != approval.StatusUsed || used.DecidedBy != "ada@acme.example" ||
			!used.UsedAt.Equal(at.Add(time.Second)) || !used.ValidUntil.Equal(at.Add(time.Minute)) {
			t.Errorf("final state = %+v", used)
		}
		if string(used.Arguments) != `{"amount":5000}` || len(used.Tokens) != 2 || used.Tokens[0].Hash != sha256.Sum256([]byte("ada-secret")) {
			t.Errorf("arguments or tokens lost: %s %+v", used.Arguments, used.Tokens)
		}
		rejected, _ := st.GetApproval(ctx, "apr_3")
		if rejected.Status != approval.StatusRejected || !rejected.ValidUntil.IsZero() {
			t.Errorf("rejected = %+v", rejected)
		}
	})
}

func TestConcurrentUseApproval(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		_ = st.CreateApproval(ctx, pendingApproval("apr_1", "h"))
		_, _ = st.DecideApproval(ctx, "apr_1", approval.StatusApproved, "ada@acme.example", at, at.Add(time.Hour))

		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := st.UseApproval(ctx, "apr_1", at.Add(time.Second)); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Errorf("%d goroutines used the approval, want exactly 1", wins)
		}
	})
}

func TestMarkReceiptUsed(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins, used := 0, 0
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := st.MarkReceiptUsed(ctx, "rcpt_1", at, at.Add(5*time.Minute))
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					wins++
				case errors.Is(err, verify.ErrAlreadyUsed):
					used++
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		wg.Wait()
		if wins != 1 || used != 19 {
			t.Errorf("wins = %d, already-used = %d; want 1 and 19", wins, used)
		}
		if err := st.MarkReceiptUsed(ctx, "rcpt_2", at, at.Add(5*time.Minute)); err != nil {
			t.Errorf("a different receipt: %v", err)
		}
	})
}

func TestMigrationsAreIdempotent(t *testing.T) {
	url := os.Getenv("CONSEQUENCE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set CONSEQUENCE_TEST_DATABASE_URL to run Postgres tests")
	}
	st := newTestPostgres(t).(*Postgres)
	if err := st.migrate(context.Background()); err != nil {
		t.Errorf("second migrate: %v", err)
	}
	n, err := st.PruneUsedReceipts(context.Background(), at)
	if err != nil || n != 0 {
		t.Errorf("prune on empty table: %d, %v", n, err)
	}
}

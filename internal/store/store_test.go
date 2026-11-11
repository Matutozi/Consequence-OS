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
		want.ID, want.Seq, want.Hash = oldest[0].ID, 1, oldest[0].Hash
		if !strings.HasPrefix(want.Hash, "sha256:") {
			t.Errorf("first entry has no chain hash: %+v", oldest[0])
		}
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

func TestExpireApprovals(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		due := pendingApproval("apr_due", "h1")
		due.ExpiresAt = at.Add(time.Hour)
		later := pendingApproval("apr_later", "h2")
		later.ExpiresAt = at.Add(2 * time.Hour)
		forever := pendingApproval("apr_forever", "h3") // no deadline, like rows from before expiry existed
		decided := pendingApproval("apr_decided", "h4")
		decided.ExpiresAt = at.Add(time.Hour)
		for _, a := range []approval.Approval{due, later, forever, decided} {
			if err := st.CreateApproval(ctx, a); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := st.DecideApproval(ctx, "apr_decided", approval.StatusRejected, "bo@acme.example", at, time.Time{}); err != nil {
			t.Fatal(err)
		}
		got, _ := st.GetApproval(ctx, "apr_due")
		if !got.ExpiresAt.Equal(due.ExpiresAt) {
			t.Errorf("expires_at round trip: %v, want %v", got.ExpiresAt, due.ExpiresAt)
		}

		// An overdue approval can't be decided any more, even before a sweep.
		if _, err := st.DecideApproval(ctx, "apr_due", approval.StatusApproved, "ada@acme.example", at.Add(time.Hour), at.Add(2*time.Hour)); !errors.Is(err, approval.ErrNotPending) {
			t.Errorf("decide when overdue: err = %v, want ErrNotPending", err)
		}

		expired, err := st.ExpireApprovals(ctx, at.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(expired) != 1 || expired[0].ID != "apr_due" || expired[0].Status != approval.StatusExpired {
			t.Fatalf("expired = %+v, want only apr_due", expired)
		}
		if again, _ := st.ExpireApprovals(ctx, at.Add(time.Hour)); len(again) != 0 {
			t.Errorf("a second sweep returned %d approvals, want 0", len(again))
		}
		for id, want := range map[string]approval.Status{
			"apr_due": approval.StatusExpired, "apr_later": approval.StatusPending,
			"apr_forever": approval.StatusPending, "apr_decided": approval.StatusRejected,
		} {
			if a, _ := st.GetApproval(ctx, id); a.Status != want {
				t.Errorf("%s: status %s, want %s", id, a.Status, want)
			}
		}
	})
}

func TestCountPendingApprovals(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		open := pendingApproval("apr_open", "h1")
		open.ExpiresAt = at.Add(time.Hour)
		forever := pendingApproval("apr_forever", "h2") // no deadline still counts
		overdue := pendingApproval("apr_overdue", "h3")
		overdue.ExpiresAt = at.Add(time.Minute)
		decided := pendingApproval("apr_decided", "h4")
		other := pendingApproval("apr_other", "h5")
		other.AgentID = "another-bot"
		for _, a := range []approval.Approval{open, forever, overdue, decided, other} {
			if err := st.CreateApproval(ctx, a); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := st.DecideApproval(ctx, "apr_decided", approval.StatusApproved, "ada@acme.example", at, at.Add(10*time.Minute)); err != nil {
			t.Fatal(err)
		}

		tests := []struct {
			agent string
			now   time.Time
			want  int
		}{
			{"bot", at, 3},                  // open, forever, overdue (not yet due)
			{"bot", at.Add(time.Minute), 2}, // overdue stops counting at its deadline
			{"bot", at.Add(time.Hour), 1},   // only the one with no deadline is left
			{"another-bot", at, 1},          // counts are per agent
			{"nobody", at, 0},
		}
		for _, tt := range tests {
			n, err := st.CountPendingApprovals(ctx, tt.agent, tt.now)
			if err != nil {
				t.Fatal(err)
			}
			if n != tt.want {
				t.Errorf("CountPendingApprovals(%s, %s) = %d, want %d", tt.agent, tt.now.Sub(at), n, tt.want)
			}
		}
	})
}

func TestPruneUsedReceipts(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		_ = st.MarkReceiptUsed(ctx, "rcpt_old", at, at.Add(time.Minute))
		_ = st.MarkReceiptUsed(ctx, "rcpt_new", at, at.Add(time.Hour))

		n, err := st.PruneUsedReceipts(ctx, at.Add(2*time.Minute))
		if err != nil || n != 1 {
			t.Fatalf("pruned %d (err %v), want 1", n, err)
		}
		// The unexpired one is still remembered, so it can't be replayed.
		if err := st.MarkReceiptUsed(ctx, "rcpt_new", at, at.Add(time.Hour)); !errors.Is(err, verify.ErrAlreadyUsed) {
			t.Errorf("rcpt_new after prune: err = %v, want ErrAlreadyUsed", err)
		}
	})
}

func TestUsage(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		records := []policy.UsageRecord{
			{AgentID: "bot", Tool: "payments.refund", At: at.Add(-25 * time.Hour), Values: map[string]float64{"amount": 1000}}, // outside a 24h window
			{AgentID: "bot", Tool: "payments.refund", At: at.Add(-2 * time.Hour), Values: map[string]float64{"amount": 120.5}},
			{AgentID: "bot", Tool: "payments.refund", At: at.Add(-time.Hour), Values: map[string]float64{"amount": 30}},
			{AgentID: "bot", Tool: "payments.refund", At: at},                                              // no summed values
			{AgentID: "other", Tool: "payments.refund", At: at, Values: map[string]float64{"amount": 999}}, // another agent
			{AgentID: "bot", Tool: "payments.charge", At: at, Values: map[string]float64{"amount": 999}},   // another tool
		}
		for _, r := range records {
			if err := st.RecordUsage(ctx, r); err != nil {
				t.Fatal(err)
			}
		}

		tests := []struct {
			name      string
			since     time.Time
			sumArg    string
			wantCount int
			wantSum   float64
		}{
			{"last 24 hours", at.Add(-24 * time.Hour), "amount", 3, 150.5},
			{"count only", at.Add(-24 * time.Hour), "", 3, 0},
			{"since itself is left out", at.Add(-time.Hour), "amount", 1, 0},
			{"argument never recorded", at.Add(-24 * time.Hour), "fee", 3, 0},
			{"everything", at.Add(-48 * time.Hour), "amount", 4, 1150.5},
		}
		for _, tt := range tests {
			count, sum, err := st.CountUsage(ctx, "bot", "payments.refund", tt.since, tt.sumArg)
			if err != nil || count != tt.wantCount || sum != tt.wantSum {
				t.Errorf("%s: got (%d, %g, %v), want (%d, %g)", tt.name, count, sum, err, tt.wantCount, tt.wantSum)
			}
		}

		n, err := st.PruneUsage(ctx, at.Add(-24*time.Hour))
		if err != nil || n == 0 {
			t.Fatalf("prune: %d, %v", n, err)
		}
		if count, _, _ := st.CountUsage(ctx, "bot", "payments.refund", at.Add(-48*time.Hour), ""); count != 3 {
			t.Errorf("after prune: %d calls, want 3", count)
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

func TestAuditChain(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		if _, ok, err := st.LastAudit(ctx); ok || err != nil {
			t.Fatalf("empty log: ok=%v err=%v", ok, err)
		}
		var last audit.Entry
		for i := 0; i < 5; i++ {
			// Nanoseconds are rounded away, so the hash still matches after a database round trip.
			e, err := st.AppendAudit(ctx, audit.Entry{Time: at.Add(time.Duration(i)*time.Second + 789), AgentID: "bot", OwnerID: "o",
				Tool: "payments.refund", Outcome: audit.OutcomeForwarded})
			if err != nil {
				t.Fatal(err)
			}
			if e.PrevHash != last.Hash {
				t.Fatalf("entry %d links to %q, want %q", i, e.PrevHash, last.Hash)
			}
			last = e
		}
		head, ok, err := st.LastAudit(ctx)
		if !ok || err != nil || head.ID != last.ID || head.Hash != last.Hash {
			t.Errorf("LastAudit = %+v, %v, %v", head, ok, err)
		}
		r, err := audit.VerifyChain(ctx, st)
		if err != nil || !r.Intact || r.Checked != 5 || r.HeadHash != last.Hash {
			t.Errorf("report = %+v, err = %v", r, err)
		}
	})
}

func TestConcurrentAppendsKeepOneChain(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		var wg sync.WaitGroup
		for i := 0; i < 40; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := st.AppendAudit(ctx, audit.Entry{Time: at, AgentID: "bot", OwnerID: "o", Tool: "x", Outcome: audit.OutcomeForwarded}); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if r, err := audit.VerifyChain(ctx, st); err != nil || !r.Intact || r.Checked != 40 {
			t.Errorf("report = %+v, err = %v (a fork or a lost link)", r, err)
		}
	})
}

// tamper changes the stored log behind the store's back, as someone with
// direct database access could.
func tamper(t *testing.T, st Store, how string, id string) {
	t.Helper()
	switch s := st.(type) {
	case *Memory:
		s.mu.Lock()
		defer s.mu.Unlock()
		for i := range s.audit {
			if s.audit[i].ID != id {
				continue
			}
			if how == "edit" {
				s.audit[i].Summary = "nothing to see here"
			} else {
				s.audit = append(s.audit[:i], s.audit[i+1:]...)
			}
			return
		}
	case *Postgres:
		query := `UPDATE audit_entries SET summary = 'nothing to see here' WHERE id = $1`
		if how == "delete" {
			query = `DELETE FROM audit_entries WHERE id = $1`
		}
		if _, err := s.pool.Exec(context.Background(), query, id); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("could not tamper with %s", id)
}

func TestTamperingIsDetected(t *testing.T) {
	for _, how := range []string{"edit", "delete"} {
		t.Run(how, func(t *testing.T) {
			forEachStore(t, func(t *testing.T, st Store) {
				ctx := context.Background()
				var ids []string
				for i := 0; i < 4; i++ {
					e, err := st.AppendAudit(ctx, audit.Entry{Time: at, AgentID: "bot", OwnerID: "o", Tool: "x", Outcome: audit.OutcomeForwarded})
					if err != nil {
						t.Fatal(err)
					}
					ids = append(ids, e.ID)
				}
				tamper(t, st, how, ids[1])
				r, err := audit.VerifyChain(ctx, st)
				want := ids[1] // an edited entry fails its own hash
				if how == "delete" {
					want = ids[2] // the entry after a deleted one no longer links
				}
				if err != nil || r.Intact || r.BrokenAt != want {
					t.Errorf("report = %+v, err = %v; want broken at %s", r, err, want)
				}
			})
		})
	}
}

func TestChainStartsAfterOlderRows(t *testing.T) {
	st, ok := newTestPostgres(t).(*Postgres)
	if !ok {
		t.Skip("postgres only")
	}
	ctx := context.Background()
	// Rows from before migration 0004 have empty hashes.
	for _, id := range []string{"aud_old0000000001", "aud_old0000000002"} {
		if _, err := st.pool.Exec(ctx, `INSERT INTO audit_entries (id, time, agent_id, owner_id, tool, outcome)
			VALUES ($1, $2, 'bot', 'o', 'x', 'forwarded')`, id, at); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := st.AppendAudit(ctx, audit.Entry{Time: at, AgentID: "bot", OwnerID: "o", Tool: "x", Outcome: audit.OutcomeForwarded}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := audit.VerifyChain(ctx, st)
	if err != nil || !r.Intact || r.Unhashed != 2 || r.Checked != 3 {
		t.Errorf("report = %+v, err = %v", r, err)
	}
}

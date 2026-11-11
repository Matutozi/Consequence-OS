package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// newTestFile opens a file store in a fresh directory, for the shared tests.
func newTestFile(t *testing.T) Store {
	t.Helper()
	return openFile(t, t.TempDir())
}

func openFile(t *testing.T, dir string) *File {
	t.Helper()
	st, err := OpenFile(dir, FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

func appendEntries(t *testing.T, st Store, n int) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	for i := 0; i < n; i++ {
		e, err := st.AppendAudit(context.Background(), audit.Entry{Time: at.Add(time.Duration(i) * time.Second), AgentID: "bot", OwnerID: "o",
			Tool: "payments.refund", Summary: "payments.refund with amount", Outcome: audit.OutcomeForwarded, Score: 80})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func journalOf(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, journalName))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeJournal(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, journalName), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileSurvivesARestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := openFile(t, dir)

	entries := appendEntries(t, st, 3)
	for _, id := range []string{"apr_used", "apr_pending"} {
		if err := st.CreateApproval(ctx, pendingApproval(id, "h_"+id)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.DecideApproval(ctx, "apr_used", approval.StatusApproved, "ada@acme.example", at, at.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UseApproval(ctx, "apr_used", at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkReceiptUsed(ctx, "rcpt_1", at, at.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordUsage(ctx, policy.UsageRecord{AgentID: "bot", Tool: "payments.*", At: at, Values: map[string]float64{"amount": 60}}); err != nil {
		t.Fatal(err)
	}
	used, _ := st.GetApproval(ctx, "apr_used")
	pending, _ := st.GetApproval(ctx, "apr_pending")
	st.Close()

	st = openFile(t, dir)
	r, err := audit.VerifyChain(ctx, st)
	if err != nil || !r.Intact || r.Checked != 3 || r.HeadHash != entries[2].Hash {
		t.Errorf("chain after restart = %+v, %v", r, err)
	}
	for _, want := range []approval.Approval{used, pending} {
		if got, err := st.GetApproval(ctx, want.ID); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("approval after restart:\n got %+v, %v\nwant %+v", got, err, want)
		}
	}
	// The receipt can't be used again: the restart forgot nothing.
	if err := st.MarkReceiptUsed(ctx, "rcpt_1", at, at.Add(5*time.Minute)); !errors.Is(err, verify.ErrAlreadyUsed) {
		t.Errorf("replayed receipt: err = %v, want ErrAlreadyUsed", err)
	}
	if n, sum, _ := st.CountUsage(ctx, "bot", "payments.*", at.Add(-time.Hour), "amount"); n != 1 || sum != 60 {
		t.Errorf("usage after restart = %d calls, %v total", n, sum)
	}
	// New entries carry on the same chain.
	e, err := st.AppendAudit(ctx, audit.Entry{Time: at, AgentID: "bot", OwnerID: "o", Tool: "x", Outcome: audit.OutcomeBlocked})
	if err != nil || e.PrevHash != entries[2].Hash || e.Seq != 4 {
		t.Errorf("next entry = %+v, %v; want it linked to entry 3", e, err)
	}
}

// requireEveryField fails if any field of the struct v is its zero value,
// so a field added later can't be left out of the round trip below.
func requireEveryField(t *testing.T, v any) {
	t.Helper()
	rv := reflect.ValueOf(v)
	for i := 0; i < rv.NumField(); i++ {
		if rv.Field(i).IsZero() {
			t.Errorf("%s.%s is not set in this test; set it, and check the journal keeps it", rv.Type().Name(), rv.Type().Field(i).Name)
		}
	}
}

func TestJournalKeepsEveryField(t *testing.T) {
	a := pendingApproval("apr_1", "h1")
	a.Arguments = []byte(`{"amount":5000,"note":"<b>&</b>"}`) // HTML escaping would change these bytes
	a.ExpiresAt, a.DecidedAt, a.DecidedBy = at.Add(time.Hour), at.Add(time.Minute), "ada@acme.example"
	a.ValidUntil, a.UsedAt, a.Status = at.Add(11*time.Minute), at.Add(2*time.Minute), approval.StatusUsed
	e := audit.Entry{
		ID: "aud_1", Time: at, AgentID: "bot", OwnerID: "o", Tool: "payments.refund", ParamsHash: "sha256:p",
		Summary: "payments.refund with amount", Level: policy.LevelIrreversible, Score: 80, Decision: policy.ActionAsk,
		Rule: "big-refunds", Outcome: audit.OutcomeForwarded, ApprovalID: "apr_1", ReceiptID: "rcpt_1",
		Detail: "d", Seq: 7, PrevHash: "sha256:prev", Hash: "sha256:h",
	}
	u := policy.UsageRecord{AgentID: "bot", Tool: "payments.*", At: at, Values: map[string]float64{"amount": 12.5}}
	for _, v := range []any{a, e, u} {
		requireEveryField(t, v)
	}

	for _, rec := range []*record{
		{Op: opApproval, Approval: newApprovalRecord(a)},
		{Op: opAudit, Audit: &e},
		{Op: opUsage, Usage: newUsageRecord(u)},
	} {
		line, err := encodeRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeRecord(line)
		if err != nil {
			t.Fatal(err)
		}
		switch rec.Op {
		case opApproval:
			back, err := got.Approval.approval()
			if err != nil || !reflect.DeepEqual(back, a) {
				t.Errorf("approval round trip:\n got %+v\nwant %+v", back, a)
			}
		case opAudit:
			if !reflect.DeepEqual(*got.Audit, e) {
				t.Errorf("audit round trip:\n got %+v\nwant %+v", *got.Audit, e)
			}
		case opUsage:
			if !reflect.DeepEqual(got.Usage.usage(), u) {
				t.Errorf("usage round trip: got %+v", got.Usage.usage())
			}
		}
	}
}

func TestTornLastLineIsDropped(t *testing.T) {
	for name, tail := range map[string]string{
		"cut short":   `{"op":"audit","audit":{"id":"aud_x","ti`,
		"zeroes":      "\x00\x00\x00\x00",
		"unreadable":  "not json\n",
		"half a line": `{"op":"receipt","id":"rcpt_9"`,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			st := openFile(t, dir)
			appendEntries(t, st, 2)
			st.Close()
			writeJournal(t, dir, journalOf(t, dir)+tail)

			var logs bytes.Buffer
			st2, err := OpenFile(dir, FileOptions{Log: slog.New(slog.NewTextHandler(&logs, nil))})
			if err != nil {
				t.Fatalf("a torn last line must not stop the store opening: %v", err)
			}
			if !strings.Contains(logs.String(), "dropped a torn last line") {
				t.Errorf("no warning logged: %s", logs.String())
			}
			// The torn bytes are cut off, so the next line starts cleanly.
			appendEntries(t, st2, 1)
			st2.Close()
			st3 := openFile(t, dir)
			if r, err := audit.VerifyChain(ctx, st3); err != nil || !r.Intact || r.Checked != 3 {
				t.Errorf("chain = %+v, %v", r, err)
			}
		})
	}
}

func TestDamagedJournalFailsToOpen(t *testing.T) {
	tests := map[string]func(lines []string) []string{
		"garbage in the middle": func(l []string) []string { return append([]string{l[0], "garbage"}, l[1:]...) },
		"unknown operation":     func(l []string) []string { return append([]string{`{"op":"teleport"}`}, l...) },
		"unknown field":         func(l []string) []string { return append([]string{`{"op":"audit","colour":"red"}`}, l...) },
		"use before approve": func(l []string) []string {
			return append(l, `{"op":"approval","approval":{"id":"apr_1","status":"pending"}}`, `{"op":"use","id":"apr_1","at":"2026-11-02T10:00:00Z"}`, l[0])
		},
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			st := openFile(t, dir)
			appendEntries(t, st, 2)
			st.Close()
			lines := strings.Split(strings.TrimSuffix(journalOf(t, dir), "\n"), "\n")
			writeJournal(t, dir, strings.Join(edit(lines), "\n")+"\n")

			if _, err := OpenFile(dir, FileOptions{}); err == nil || !strings.Contains(err.Error(), "line ") {
				t.Errorf("err = %v, want one naming the bad line", err)
			}
		})
	}
}

func TestEditedJournalIsCaughtByVerify(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := openFile(t, dir)
	entries := appendEntries(t, st, 3)
	st.Close()
	// Someone with access to the disk lowers an entry's score.
	writeJournal(t, dir, strings.Replace(journalOf(t, dir), `"score":80`, `"score":5`, 1))

	st = openFile(t, dir)
	r, err := audit.VerifyChain(ctx, st)
	if err != nil || r.Intact || r.BrokenAt != entries[0].ID {
		t.Errorf("report = %+v, %v; want broken at %s", r, err, entries[0].ID)
	}
}

func TestSecondOpenWaitsForTheLock(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	first := openFile(t, dir)
	head := appendEntries(t, first, 2)[1]

	if _, err := OpenFile(dir, FileOptions{LockTimeout: 50 * time.Millisecond}); !errors.Is(err, ErrLocked) {
		t.Fatalf("second open: err = %v, want ErrLocked", err)
	}

	opened := make(chan *File, 1)
	go func() {
		st, err := OpenFile(dir, FileOptions{LockTimeout: 5 * time.Second})
		if err != nil {
			t.Error(err)
		}
		opened <- st
	}()
	time.Sleep(50 * time.Millisecond)
	first.Close()
	second := <-opened
	if second == nil {
		t.FailNow()
	}
	defer second.Close()
	// The second sees everything the first wrote and continues its chain.
	e, err := second.AppendAudit(ctx, audit.Entry{Time: at, AgentID: "bot", OwnerID: "o", Tool: "x", Outcome: audit.OutcomeForwarded})
	if err != nil || e.PrevHash != head.Hash || e.Seq != 3 {
		t.Errorf("entry = %+v, %v; want it after the first process's entries", e, err)
	}
}

// TestHelperHoldsTheLock is not a test: TestCrashedProcessFreesTheLock runs
// the test binary again with this as the only test, to hold the lock in
// another process and be killed.
func TestHelperHoldsTheLock(t *testing.T) {
	dir := os.Getenv("CONSEQUENCE_TEST_HOLD_LOCK")
	if dir == "" {
		t.Skip("only run by TestCrashedProcessFreesTheLock")
	}
	st, err := OpenFile(dir, FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	appendEntries(t, st, 1)
	os.Stdout.WriteString("locked\n")
	time.Sleep(time.Minute) // until killed
}

func TestCrashedProcessFreesTheLock(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a process")
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldsTheLock$", "-test.v")
	cmd.Env = append(os.Environ(), "CONSEQUENCE_TEST_HOLD_LOCK="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	var seen string
	for !strings.Contains(seen, "locked") {
		n, err := out.Read(buf)
		if err != nil {
			t.Fatalf("helper exited before taking the lock: %v (%q)", err, seen)
		}
		seen += string(buf[:n])
	}
	if _, err := OpenFile(dir, FileOptions{LockTimeout: 50 * time.Millisecond}); !errors.Is(err, ErrLocked) {
		t.Fatalf("while the other process runs: err = %v, want ErrLocked", err)
	}

	_ = cmd.Process.Kill() // like a hook killed for taking too long
	_ = cmd.Wait()
	st, err := OpenFile(dir, FileOptions{LockTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("after the other process died: %v", err)
	}
	defer st.Close()
	if r, err := audit.VerifyChain(context.Background(), st); err != nil || !r.Intact || r.Checked != 1 {
		t.Errorf("chain = %+v, %v", r, err)
	}
}

func TestReadOnly(t *testing.T) {
	ctx := context.Background()
	t.Run("while another process has it open", func(t *testing.T) {
		dir := t.TempDir()
		writer := openFile(t, dir)
		appendEntries(t, writer, 2)

		ro, err := OpenFile(dir, FileOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer ro.Close()
		if r, err := audit.VerifyChain(ctx, ro); err != nil || !r.Intact || r.Checked != 2 {
			t.Errorf("chain = %+v, %v", r, err)
		}
		if _, err := ro.AppendAudit(ctx, audit.Entry{Tool: "x"}); !errors.Is(err, ErrReadOnly) {
			t.Errorf("append: err = %v, want ErrReadOnly", err)
		}
		if err := ro.MarkReceiptUsed(ctx, "rcpt_1", at, at); !errors.Is(err, ErrReadOnly) {
			t.Errorf("receipt: err = %v, want ErrReadOnly", err)
		}
	})
	t.Run("nothing recorded yet", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "missing")
		ro, err := OpenFile(dir, FileOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := ro.LastAudit(ctx); ok {
			t.Error("an empty store has entries")
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Error("read-only open created the directory")
		}
	})
}

func TestCompaction(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := openFile(t, dir)
	st.minCompact = 1 // compact whenever the journal doubles

	entries := appendEntries(t, st, 3)
	for i, id := range []string{"apr_1", "apr_2"} {
		a := pendingApproval(id, "h"+id)
		a.ExpiresAt = at.Add(time.Duration(i+1) * time.Hour)
		if err := st.CreateApproval(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.DecideApproval(ctx, "apr_1", approval.StatusApproved, "ada@acme.example", at, at.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ExpireApprovals(ctx, at.Add(90*time.Minute)); err != nil { // apr_2 is still in time
		t.Fatal(err)
	}
	for i, exp := range []time.Duration{time.Minute, time.Hour} {
		if err := st.MarkReceiptUsed(ctx, "rcpt_"+string(rune('a'+i)), at, at.Add(exp)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.PruneUsedReceipts(ctx, at.Add(30*time.Minute)); err != nil { // forgets rcpt_a
		t.Fatal(err)
	}
	for _, when := range []time.Time{at.Add(-48 * time.Hour), at} {
		if err := st.RecordUsage(ctx, policy.UsageRecord{AgentID: "bot", Tool: "payments.*", At: when, Values: map[string]float64{"amount": 10}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.PruneUsage(ctx, at.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Force one more compaction now, so the journal reflects everything above.
	st.mu.Lock()
	st.base = 0
	st.compact()
	st.mu.Unlock()

	journal := journalOf(t, dir)
	for _, gone := range []string{`"op":"decide"`, `"op":"expire"`, `"op":"prune_receipts"`, `"op":"prune_usage"`, `"rcpt_a"`} {
		if strings.Contains(journal, gone) {
			t.Errorf("compacted journal still has %s:\n%s", gone, journal)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, journalName+".tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Error("compaction left its temporary file behind")
	}
	want1, _ := st.GetApproval(ctx, "apr_1")
	want2, _ := st.GetApproval(ctx, "apr_2")
	appendEntries(t, st, 1) // the compacted journal is still the one being written
	st.Close()

	st = openFile(t, dir)
	if r, err := audit.VerifyChain(ctx, st); err != nil || !r.Intact || r.Checked != 4 {
		t.Errorf("chain = %+v, %v", r, err)
	}
	if head, _, _ := st.LastAudit(ctx); head.PrevHash != entries[2].Hash {
		t.Error("the entry written after compaction doesn't follow the compacted ones")
	}
	for _, want := range []approval.Approval{want1, want2} {
		if got, _ := st.GetApproval(ctx, want.ID); !reflect.DeepEqual(got, want) {
			t.Errorf("approval after compaction:\n got %+v\nwant %+v", got, want)
		}
	}
	if err := st.MarkReceiptUsed(ctx, "rcpt_b", at, at.Add(time.Hour)); !errors.Is(err, verify.ErrAlreadyUsed) {
		t.Errorf("rcpt_b after compaction: %v, want ErrAlreadyUsed", err)
	}
	if n, _, _ := st.CountUsage(ctx, "bot", "payments.*", at.Add(-72*time.Hour), ""); n != 1 {
		t.Errorf("usage after compaction = %d, want 1", n)
	}
}

func TestFailedJournalWriteStopsTheStore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := openFile(t, dir)
	appendEntries(t, st, 1)
	_ = st.journal.Close() // the disk goes away underneath it

	if _, err := st.AppendAudit(ctx, audit.Entry{Time: at, AgentID: "bot", Tool: "x", Outcome: audit.OutcomeForwarded}); err == nil {
		t.Fatal("append succeeded without reaching the journal")
	}
	// Memory now holds an entry the journal doesn't, so nothing may read it.
	if _, err := st.ListAudit(ctx, audit.Filter{}); err == nil {
		t.Error("reads still work after a failed write")
	}
	if _, _, err := st.CountUsage(ctx, "bot", "x", at, ""); err == nil {
		t.Error("usage still counts after a failed write")
	}
	if err := st.MarkReceiptUsed(ctx, "rcpt_1", at, at); err == nil {
		t.Error("writes still work after a failed write")
	}
	st.Close()

	st = openFile(t, dir)
	if r, err := audit.VerifyChain(ctx, st); err != nil || !r.Intact || r.Checked != 1 {
		t.Errorf("after a restart: %+v, %v; want the one journaled entry", r, err)
	}
}

func TestFileModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	st := openFile(t, dir)
	appendEntries(t, st, 1)
	for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, journalName): 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", path, got, want)
		}
	}
	// The journal holds token hashes, never the secrets.
	if err := st.CreateApproval(context.Background(), pendingApproval("apr_1", "h1")); err != nil {
		t.Fatal(err)
	}
	if j := journalOf(t, dir); strings.Contains(j, "ada-secret") || !strings.Contains(j, hexSum("ada-secret")) {
		t.Error("the journal should hold the token's hash and not the token")
	}
}

func hexSum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

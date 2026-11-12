package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matutozi/consequence-os/internal/audit"
)

func TestArchiveAudit(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		entries := appendEntries(t, st, 5)
		if _, ok, err := st.AuditAnchor(ctx); ok || err != nil {
			t.Fatalf("an anchor before any archive: %v %v", ok, err)
		}
		third := entries[2]
		for _, bad := range []audit.Anchor{
			{Seq: third.Seq, Hash: "sha256:wrong", At: at},
			{Seq: entries[4].Seq + 100, Hash: third.Hash, At: at},
		} {
			if _, err := st.ArchiveAudit(ctx, bad); err == nil {
				t.Errorf("archived up to %+v", bad)
			}
		}
		anchor := audit.Anchor{Seq: third.Seq, Hash: third.Hash, Head: json.RawMessage(`{"signed":"head"}`), At: at}
		n, err := st.ArchiveAudit(ctx, anchor)
		if err != nil || n != 3 {
			t.Fatalf("ArchiveAudit = %d, %v; want 3", n, err)
		}
		got, ok, err := st.AuditAnchor(ctx)
		if err != nil || !ok || got.Seq != anchor.Seq || got.Hash != anchor.Hash || string(got.Head) != string(anchor.Head) || !got.At.Equal(at) {
			t.Errorf("anchor = %+v, %v, %v", got, ok, err)
		}
		var left []int64
		_ = st.ForEachAudit(ctx, func(e audit.Entry) error { left = append(left, e.Seq); return nil })
		if len(left) != 2 || left[0] != entries[3].Seq {
			t.Errorf("entries left: %v", left)
		}
		r, err := audit.VerifyChain(ctx, st)
		if err != nil || !r.Intact || r.Checked != 2 || r.ArchivedThrough != third.Seq || r.Anchor != audit.AnchorNotChecked {
			t.Errorf("chain after archiving = %+v, %v", r, err)
		}
		if _, err := st.ArchiveAudit(ctx, anchor); err == nil {
			t.Error("archived the same entries twice")
		}

		// Archive the rest: the next entry links to the anchor, and its
		// seq carries on.
		last := entries[4]
		if n, err := st.ArchiveAudit(ctx, audit.Anchor{Seq: last.Seq, Hash: last.Hash, At: at}); err != nil || n != 2 {
			t.Fatalf("archiving the rest = %d, %v", n, err)
		}
		if _, ok, _ := st.LastAudit(ctx); ok {
			t.Error("entries left after archiving them all")
		}
		next := appendEntries(t, st, 1)[0]
		if next.PrevHash != last.Hash || next.Seq <= last.Seq {
			t.Errorf("the entry after archiving everything: seq %d, prev %s; want after %d, %s", next.Seq, next.PrevHash, last.Seq, last.Hash)
		}
		if r, err := audit.VerifyChain(ctx, st); err != nil || !r.Intact || r.Checked != 1 {
			t.Errorf("chain = %+v, %v", r, err)
		}
	})
}

// The anchor's signed head is checked when a checker is given, and an
// anchor whose head names another entry breaks the chain.
func TestArchiveAnchorIsChecked(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()
	entries := appendEntries(t, st, 3)
	if _, err := st.ArchiveAudit(ctx, audit.Anchor{Seq: entries[1].Seq, Hash: entries[1].Hash, Head: json.RawMessage(`"head"`), At: at}); err != nil {
		t.Fatal(err)
	}
	good := func([]byte) (int64, string, error) { return entries[1].Seq, entries[1].Hash, nil }
	other := func([]byte) (int64, string, error) { return entries[0].Seq, entries[0].Hash, nil }
	if r, _ := audit.VerifyChainWith(ctx, st, &audit.ChainVerifier{CheckHead: good}); !r.Intact || r.Anchor != audit.AnchorChecked {
		t.Errorf("a good anchor: %+v", r)
	}
	if r, _ := audit.VerifyChainWith(ctx, st, &audit.ChainVerifier{CheckHead: other}); r.Intact || !strings.Contains(r.Problem, "anchor") {
		t.Errorf("an anchor whose head names another entry: %+v", r)
	}
	// A saved head inside the archive doesn't count as missing from the end.
	v := &audit.ChainVerifier{CheckHead: good}
	v.ExpectHead(entries[0].Seq, entries[0].Hash)
	if r, _ := audit.VerifyChainWith(ctx, st, v); !r.Intact {
		t.Errorf("a saved head from before the anchor: %+v", r)
	}
	v = &audit.ChainVerifier{}
	v.ExpectHead(entries[1].Seq, "sha256:other")
	if r, _ := audit.VerifyChainWith(ctx, st, v); r.Intact {
		t.Errorf("a saved head at the anchor with another hash: %+v", r)
	}
}

func TestFileArchiveLeavesTheDisk(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := openFile(t, dir)
	entries := appendEntries(t, st, 4)
	if _, err := st.ArchiveAudit(ctx, audit.Anchor{Seq: entries[1].Seq, Hash: entries[1].Hash, At: at}); err != nil {
		t.Fatal(err)
	}
	journal := journalOf(t, dir)
	for _, gone := range entries[:2] {
		if strings.Contains(journal, gone.ID) {
			t.Errorf("archived entry %s is still in the journal", gone.ID)
		}
	}
	appendEntries(t, st, 1)
	st.Close()

	st = openFile(t, dir)
	if a, ok, _ := st.AuditAnchor(ctx); !ok || a.Seq != entries[1].Seq {
		t.Errorf("anchor after a restart: %+v, %v", a, ok)
	}
	if r, err := audit.VerifyChain(ctx, st); err != nil || !r.Intact || r.Checked != 3 {
		t.Errorf("chain after a restart = %+v, %v", r, err)
	}
	ro, err := OpenFile(dir, FileOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ro.ArchiveAudit(ctx, audit.Anchor{Seq: entries[2].Seq, Hash: entries[2].Hash, At: at}); err == nil {
		t.Error("a read-only store archived")
	}
}

// With every entry archived, GET /v1/audit/head signs the anchor: the
// chain ends there until the next entry.
func TestHeadAfterArchivingEverything(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()
	entries := appendEntries(t, st, 2)
	last := entries[1]
	var signed string
	sign := func(seq int64, hash string) ([]byte, error) {
		signed = fmt.Sprintf("%d %s", seq, hash)
		return []byte(`{}`), nil
	}
	h := audit.HeadHandler(st, sign, "admin", slog.New(slog.NewTextHandler(io.Discard, nil)))
	get := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/v1/audit/head", nil)
		req.Header.Set("Authorization", "Bearer admin")
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if _, err := st.ArchiveAudit(ctx, audit.Anchor{Seq: last.Seq, Hash: last.Hash, At: at}); err != nil {
		t.Fatal(err)
	}
	if code := get(); code != 200 || signed != fmt.Sprintf("%d %s", last.Seq, last.Hash) {
		t.Errorf("head with everything archived: %d, signed %q", code, signed)
	}
	empty := audit.HeadHandler(NewMemory(), sign, "admin", slog.New(slog.NewTextHandler(io.Discard, nil)))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/audit/head", nil)
	req.Header.Set("Authorization", "Bearer admin")
	empty.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Errorf("head of a log never written: %d, want 404", rec.Code)
	}
}

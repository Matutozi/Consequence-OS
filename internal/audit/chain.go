package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/matutozi/consequence-os/pkg/verify"
)

// The audit log is a hash chain: each entry stores the hash of the one
// before it, and its own hash covers that link and every field. Editing,
// deleting or reordering an entry breaks every link after it. A signed
// head (see Head) pins the chain's end so a wholesale rewrite shows too.

// Precision is what entry times are rounded to before hashing. Postgres
// keeps microseconds, so a nanosecond time would hash differently once
// read back.
const Precision = time.Microsecond

// hashed is exactly what an entry's hash covers: every field except the
// chain fields themselves and seq, which the database assigns (and may
// skip numbers in) only after the hash is made.
type hashed struct {
	ID         string `json:"id"`
	Time       string `json:"time"`
	AgentID    string `json:"agent_id"`
	OwnerID    string `json:"owner_id"`
	Tool       string `json:"tool"`
	ParamsHash string `json:"params_hash"`
	Summary    string `json:"summary"`
	Level      string `json:"level"`
	Decision   string `json:"decision"`
	Rule       string `json:"rule"`
	Outcome    string `json:"outcome"`
	ApprovalID string `json:"approval_id"`
	ReceiptID  string `json:"receipt_id"`
	Detail     string `json:"detail"`
	PrevHash   string `json:"prev_hash"`
	// Fields added after the chain shipped are omitempty, so an entry
	// without them hashes exactly as it did before they existed.
	Score int `json:"score,omitempty"`
}

// ChainHash returns the hash for e when it follows an entry whose hash is
// prev ("" for the first entry of the chain): "sha256:" and the hex SHA-256
// of the entry's canonical JSON, including prev.
func ChainHash(prev string, e Entry) (string, error) {
	raw, err := json.Marshal(hashed{
		ID: e.ID, Time: e.Time.UTC().Truncate(Precision).Format(time.RFC3339Nano),
		AgentID: e.AgentID, OwnerID: e.OwnerID, Tool: e.Tool, ParamsHash: e.ParamsHash,
		Summary: e.Summary, Level: string(e.Level), Decision: string(e.Decision), Rule: e.Rule,
		Outcome: string(e.Outcome), ApprovalID: e.ApprovalID, ReceiptID: e.ReceiptID,
		Detail: e.Detail, PrevHash: prev, Score: e.Score,
	})
	if err != nil {
		return "", err
	}
	canonical, err := verify.Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("audit: canonicalize entry: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Chain links e to the entry before it: it rounds the time and fills in
// PrevHash and Hash. Stores call it while holding their append lock.
func Chain(prev string, e Entry) (Entry, error) {
	e.Time = e.Time.UTC().Truncate(Precision)
	e.PrevHash = prev
	h, err := ChainHash(prev, e)
	if err != nil {
		return Entry{}, err
	}
	e.Hash = h
	return e, nil
}

// ChainReport is the result of checking the whole log.
type ChainReport struct {
	Intact   bool   `json:"intact"`
	Checked  int    `json:"checked"`             // entries whose hash was checked
	Unhashed int    `json:"unhashed"`            // entries from before the chain existed
	BrokenAt string `json:"broken_at,omitempty"` // ID of the first entry that doesn't fit
	Problem  string `json:"problem,omitempty"`
	HeadSeq  int64  `json:"head_seq,omitempty"` // the last entry checked
	HeadHash string `json:"head_hash,omitempty"`
	// ArchivedThrough is the last entry archived and deleted, when older
	// entries were: the chain is checked from there (see Anchor).
	ArchivedThrough int64 `json:"archived_through,omitempty"`
	// Anchor says how far the anchor was checked: AnchorChecked,
	// AnchorUnsigned or AnchorNotChecked. Empty when nothing was archived.
	Anchor string `json:"anchor,omitempty"`
}

// How far an anchor was checked.
const (
	AnchorChecked    = "signature checked"
	AnchorUnsigned   = "unsigned"              // archived in a local mode, which has no signing keys
	AnchorNotChecked = "signature not checked" // no keys to check it with were given
)

// ChainVerifier checks entries one at a time, oldest first, so a long log
// never has to fit in memory.
type ChainVerifier struct {
	report  ChainReport
	started bool // seen the first hashed entry
	prev    string

	// A saved head to hold the log to, if any (see ExpectHead).
	headSeq  int64
	headHash string
	headSeen bool

	// CheckHead checks the signed head of an anchor. nil leaves it
	// unchecked, and the report says so.
	CheckHead HeadChecker
}

// HeadChecker checks a signed audit head and returns the entry it names.
type HeadChecker func(signed []byte) (seq int64, hash string, err error)

// StartAfter makes the check start after an anchor: the first entry must
// link to the anchor's hash, as if the archived entries were still there.
// It checks the anchor's head with CheckHead, if both are there, and
// returns why the anchor can't be trusted, if it can't.
func (v *ChainVerifier) StartAfter(a Anchor) error {
	v.started, v.prev = true, a.Hash
	v.report.ArchivedThrough = a.Seq
	status, err := a.check(v.CheckHead)
	v.report.Anchor = status
	if err != nil {
		v.report.Problem = "the anchor where the log starts after archiving doesn't check out: " + err.Error()
		return err
	}
	// A saved head from before the anchor is in an archive: check it
	// there, with consequenced -verify-audit -archive.
	if v.headSeq != 0 && v.headSeq <= a.Seq {
		if v.headSeq == a.Seq && v.headHash != a.Hash {
			v.report.Problem = "the saved head doesn't match the anchor where the log starts after archiving (the log was rewritten)"
			return errors.New(v.report.Problem)
		}
		v.headSeen = true
	}
	return nil
}

// ExpectHead makes the check also require that entry seq still exists with
// hash: the contents of a signed head saved earlier. That catches entries
// removed from the end of the log, which the chain alone can't see.
func (v *ChainVerifier) ExpectHead(seq int64, hash string) {
	v.headSeq, v.headHash = seq, hash
}

// Add checks the next entry. It returns false once the chain is broken;
// later entries are then ignored.
func (v *ChainVerifier) Add(e Entry) bool {
	if v.report.BrokenAt != "" {
		return false
	}
	if e.Hash == "" && !v.started {
		v.report.Unhashed++ // written before chaining existed
		return true
	}
	v.started = true
	switch want, err := ChainHash(e.PrevHash, e); {
	case e.Hash == "":
		return v.fail(e, "entry has no hash, but entries before it do")
	case e.PrevHash != v.prev:
		return v.fail(e, "entry does not link to the one before it (an entry was removed, added or moved)")
	case err != nil || e.Hash != want:
		return v.fail(e, "entry's contents don't match its hash (it was changed)")
	}
	if v.headSeq != 0 && e.Seq == v.headSeq {
		if e.Hash != v.headHash {
			return v.fail(e, "entry doesn't match the saved head (the log was rewritten)")
		}
		v.headSeen = true
	}
	v.prev = e.Hash
	v.report.Checked++
	v.report.HeadSeq, v.report.HeadHash = e.Seq, e.Hash
	return true
}

func (v *ChainVerifier) fail(e Entry, problem string) bool {
	v.report.BrokenAt, v.report.Problem = e.ID, problem
	return false
}

// Report returns the result so far.
func (v *ChainVerifier) Report() ChainReport {
	r := v.report
	if r.BrokenAt == "" && v.headSeq != 0 && !v.headSeen {
		r.Problem = fmt.Sprintf("entry %d from the saved head is missing (entries were removed from the end of the log)", v.headSeq)
	}
	r.Intact = r.BrokenAt == "" && r.Problem == ""
	return r
}

// AnchorSource gives the anchor the log starts from after archiving. The
// store implements it.
type AnchorSource interface {
	AuditAnchor(ctx context.Context) (a Anchor, ok bool, err error)
}

// Walker reads the whole log, oldest first. The store implements it.
type Walker interface {
	ForEachAudit(ctx context.Context, fn func(Entry) error) error
}

// errStop ends a walk early once the chain is known to be broken.
var errStop = errors.New("audit: stop walking")

// VerifyChain checks every entry in the log.
func VerifyChain(ctx context.Context, w Walker) (ChainReport, error) {
	return VerifyChainWith(ctx, w, &ChainVerifier{})
}

// VerifyChainWith checks every entry with a verifier set up by the caller,
// for example with ExpectHead. When w is also an AnchorSource and older
// entries were archived, the check starts after the anchor.
func VerifyChainWith(ctx context.Context, w Walker, v *ChainVerifier) (ChainReport, error) {
	if src, ok := w.(AnchorSource); ok {
		a, archived, err := src.AuditAnchor(ctx)
		if err != nil {
			return ChainReport{}, err
		}
		if archived {
			if err := v.StartAfter(a); err != nil {
				return v.Report(), nil
			}
		}
	}
	err := w.ForEachAudit(ctx, func(e Entry) error {
		if !v.Add(e) {
			return errStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		return ChainReport{}, err
	}
	return v.Report(), nil
}

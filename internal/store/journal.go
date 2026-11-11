package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
)

// The journal's operations, one per kind of change. Replaying a line
// repeats the change on the in-memory store, except audit entries, which
// are restored exactly as written: re-chaining them would hide an edit
// that consequenced -verify-audit should find.
const (
	opAudit         = "audit"
	opApproval      = "approval" // a new approval, or one approval's whole state after compaction
	opDecide        = "decide"
	opUse           = "use"
	opExpire        = "expire"
	opReceipt       = "receipt"
	opPruneReceipts = "prune_receipts"
	opUsage         = "usage"
	opPruneUsage    = "prune_usage"
)

// record is one line of the journal.
type record struct {
	Op       string          `json:"op"`
	Audit    *audit.Entry    `json:"audit,omitempty"`
	Approval *approvalRecord `json:"approval,omitempty"`
	Usage    *usageRecord    `json:"usage,omitempty"`
	ID       string          `json:"id,omitempty"`
	Status   approval.Status `json:"status,omitempty"`
	By       string          `json:"by,omitempty"`
	At       time.Time       `json:"at,omitzero"`
	Until    time.Time       `json:"until,omitzero"`
}

// approvalRecord adds the two fields approval.Approval keeps out of JSON,
// because the API must never show them: the hashes of the approvers' link
// tokens, and the arguments shown to the approver.
type approvalRecord struct {
	approval.Approval
	Tokens    []tokenRecord   `json:"tokens,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type tokenRecord struct {
	Approver string `json:"approver"`
	Hash     string `json:"hash"` // hex sha256 of the secret, as in Postgres
}

func newApprovalRecord(a approval.Approval) *approvalRecord {
	r := &approvalRecord{Approval: a, Arguments: a.Arguments}
	for _, t := range a.Tokens {
		r.Tokens = append(r.Tokens, tokenRecord{Approver: t.Approver, Hash: hex.EncodeToString(t.Hash[:])})
	}
	return r
}

func (r *approvalRecord) approval() (approval.Approval, error) {
	a := r.Approval
	a.Arguments, a.Tokens = r.Arguments, nil
	for _, t := range r.Tokens {
		raw, err := hex.DecodeString(t.Hash)
		if err != nil || len(raw) != 32 {
			return approval.Approval{}, fmt.Errorf("approval %s: bad token hash", a.ID)
		}
		tok := approval.ApproverToken{Approver: t.Approver}
		copy(tok.Hash[:], raw)
		a.Tokens = append(a.Tokens, tok)
	}
	return a, nil
}

// usageRecord is policy.UsageRecord with JSON names of our own, so the
// journal's format doesn't depend on that struct's Go field names.
type usageRecord struct {
	AgentID string             `json:"agent_id"`
	Scope   string             `json:"scope"`
	At      time.Time          `json:"at"`
	Values  map[string]float64 `json:"values,omitempty"`
}

func newUsageRecord(u policy.UsageRecord) *usageRecord {
	return &usageRecord{AgentID: u.AgentID, Scope: u.Tool, At: u.At, Values: u.Values}
}

func (r *usageRecord) usage() policy.UsageRecord {
	return policy.UsageRecord{AgentID: r.AgentID, Tool: r.Scope, At: r.At, Values: r.Values}
}

// encodeRecord returns one journal line, ending in a newline. HTML
// escaping is off, so an approval's arguments come back byte for byte.
func encodeRecord(rec *record) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil { // Encode adds the newline
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeRecord(line []byte) (*record, error) {
	var rec record
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields() // a line from a newer version shouldn't be half understood
	if err := dec.Decode(&rec); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("more than one value on the line")
	}
	return &rec, nil
}

// replay applies every line of the journal to f.mem. It returns the offset
// just past the last good line, and whether a torn line followed it.
//
// A torn line is the last line, cut short or unreadable: a crash in the
// middle of a write. It is dropped with a warning, since the change it held
// was never reported done. A bad line anywhere else means the journal was
// damaged or edited, and opening fails rather than guess.
func (f *File) replay(r io.Reader, path string) (good int64, torn bool, err error) {
	br := bufio.NewReader(r)
	for n := 1; ; n++ {
		line, readErr := br.ReadBytes('\n')
		if len(line) == 0 && errors.Is(readErr, io.EOF) {
			return good, false, nil
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return 0, false, fmt.Errorf("store: read %s: %w", path, readErr)
		}
		_, peekErr := br.Peek(1)
		last := errors.Is(peekErr, io.EOF)

		rec, decodeErr := decodeRecord(line)
		if readErr != nil || decodeErr != nil { // no newline, or not a record
			if last {
				f.log.Warn("dropped a torn last line from the journal, left by a crash mid-write",
					"journal", path, "line", n, "bytes", len(line))
				return good, true, nil
			}
			return 0, false, fmt.Errorf("store: %s line %d is damaged: %w", path, n, decodeErr)
		}
		if err := f.mem.apply(rec); err != nil {
			return 0, false, fmt.Errorf("store: %s line %d: %w", path, n, err)
		}
		good += int64(len(line))
	}
}

// apply repeats one journaled change. The store isn't shared yet, so no
// other goroutine sees the state part way through.
func (m *Memory) apply(rec *record) error {
	ctx := context.Background()
	var err error
	switch rec.Op {
	case opAudit:
		if rec.Audit == nil {
			return errors.New("audit line without an entry")
		}
		m.mu.Lock()
		m.audit = append(m.audit, *rec.Audit)
		m.mu.Unlock()
	case opApproval:
		if rec.Approval == nil {
			return errors.New("approval line without an approval")
		}
		var a approval.Approval
		if a, err = rec.Approval.approval(); err == nil {
			err = m.CreateApproval(ctx, a)
		}
	case opDecide:
		_, err = m.DecideApproval(ctx, rec.ID, rec.Status, rec.By, rec.At, rec.Until)
	case opUse:
		_, err = m.UseApproval(ctx, rec.ID, rec.At)
	case opExpire:
		_, err = m.ExpireApprovals(ctx, rec.At)
	case opReceipt:
		err = m.MarkReceiptUsed(ctx, rec.ID, rec.At, rec.Until)
	case opPruneReceipts:
		_, err = m.PruneUsedReceipts(ctx, rec.At)
	case opUsage:
		if rec.Usage == nil {
			return errors.New("usage line without a record")
		}
		err = m.RecordUsage(ctx, rec.Usage.usage())
	case opPruneUsage:
		_, err = m.PruneUsage(ctx, rec.At)
	default:
		return fmt.Errorf("unknown operation %q; was it written by a newer consequenced?", rec.Op)
	}
	if err != nil {
		return fmt.Errorf("%s %s: %w", rec.Op, rec.ID, err)
	}
	return nil
}

// compact rewrites the journal from the current state. Callers hold f.mu,
// so nothing changes meanwhile. The new journal is written beside the old
// one and renamed over it, so a crash leaves one or the other, whole.
func (f *File) compact() {
	path := filepath.Join(f.dir, journalName)
	tmp := path + ".tmp"
	before := f.size
	size, err := f.writeSnapshot(tmp)
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		f.base = f.size // try again once it has doubled again, not on every write
		f.log.Warn("journal compaction failed; carrying on with the full journal", "journal", path, "err", err)
		return
	}
	_ = syncDir(f.dir)
	j, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		// The open file is the old journal, now unlinked: writing on to it
		// would lose every change.
		e := fmt.Errorf("store: reopen the compacted journal, so the file store refuses every request until a restart: %w", err)
		f.broken.Store(&e)
		return
	}
	_ = f.journal.Close()
	f.journal, f.size, f.base = j, size, size
	f.log.Info("journal compacted", "journal", path, "bytes_before", before, "bytes_after", size)
}

// writeSnapshot writes the current state to path as journal lines and
// syncs it. It returns the size written.
func (f *File) writeSnapshot(path string) (int64, error) {
	m := f.mem
	m.mu.Lock()
	entries := append([]audit.Entry(nil), m.audit...)
	approvals := append([]approval.Approval(nil), m.approvals...)
	usage := append([]policy.UsageRecord(nil), m.usage...)
	receipts := make([]string, 0, len(m.receipts))
	expiries := make(map[string]time.Time, len(m.receipts))
	for id, exp := range m.receipts {
		receipts = append(receipts, id)
		expiries[id] = exp
	}
	m.mu.Unlock()
	sort.Strings(receipts) // the same state always compacts to the same file

	w, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	defer w.Close()
	bw := bufio.NewWriter(w)
	var size int64
	emit := func(rec *record) error {
		line, err := encodeRecord(rec)
		if err != nil {
			return err
		}
		n, err := bw.Write(line)
		size += int64(n)
		return err
	}
	for i := range entries {
		if err := emit(&record{Op: opAudit, Audit: &entries[i]}); err != nil {
			return 0, err
		}
	}
	for _, a := range approvals {
		if err := emit(&record{Op: opApproval, Approval: newApprovalRecord(a)}); err != nil {
			return 0, err
		}
	}
	for _, id := range receipts {
		if err := emit(&record{Op: opReceipt, ID: id, Until: expiries[id]}); err != nil {
			return 0, err
		}
	}
	for _, u := range usage {
		if err := emit(&record{Op: opUsage, Usage: newUsageRecord(u)}); err != nil {
			return 0, err
		}
	}
	if err := bw.Flush(); err != nil {
		return 0, err
	}
	if err := w.Sync(); err != nil {
		return 0, err
	}
	return size, w.Close()
}

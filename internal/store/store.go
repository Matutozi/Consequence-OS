// Package store holds ConsequenceOS state behind one interface, with an
// in-memory implementation and a Postgres one.
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/toolpin"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// Store is everything the server persists. It grows as stages add receipts.
type Store interface {
	// AppendAudit saves an entry, assigning an ID if it has none, and links
	// it into the hash chain. Appends are serialized, so the chain has no forks.
	AppendAudit(ctx context.Context, e audit.Entry) (audit.Entry, error)
	// ListAudit returns matching entries, newest first.
	ListAudit(ctx context.Context, f audit.Filter) ([]audit.Entry, error)
	// ForEachAudit calls fn with every entry, oldest first, for checking the chain.
	audit.Walker
	// LastAudit returns the newest entry, or ok=false when the log is empty.
	LastAudit(ctx context.Context) (e audit.Entry, ok bool, err error)
	// AuditAnchor returns where the log starts after older entries were
	// archived, or ok=false when none were.
	audit.AnchorSource
	// ArchiveAudit deletes every entry up to and including entry a.Seq,
	// which must have hash a.Hash, and makes a the anchor, in one step:
	// the chain then starts from a. It returns how many entries it
	// deleted. Entries written later link to a.Hash when none are left.
	ArchiveAudit(ctx context.Context, a audit.Anchor) (int64, error)

	// An interface can embed another: Store includes every approval method.
	approval.Repository

	// MarkReceiptUsed records a receipt as used, or returns
	// verify.ErrAlreadyUsed. Atomic, so a receipt works exactly once.
	MarkReceiptUsed(ctx context.Context, receiptID string, usedAt, expiresAt time.Time) error
	// PruneUsedReceipts forgets used receipts that expired before now; an
	// expired receipt fails verification anyway. Returns how many it removed.
	PruneUsedReceipts(ctx context.Context, now time.Time) (int64, error)

	// Usage of forwarded calls, for limit rules. CountUsage comes from
	// policy.UsageCounter; RecordUsage saves one call; PruneUsage forgets
	// calls older than before.
	policy.UsageCounter
	RecordUsage(ctx context.Context, u policy.UsageRecord) error
	PruneUsage(ctx context.Context, before time.Time) (int64, error)

	// Pins of upstream tool definitions; see internal/toolpin.
	toolpin.Repository

	// Close releases connections. The in-memory store has nothing to release.
	Close()
}

// Memory is a Store that keeps everything in process memory. Data is lost on
// restart. Safe for use from many goroutines at once.
type Memory struct {
	mu        sync.Mutex // guards the fields below; HTTP handlers run concurrently
	audit     []audit.Entry
	approvals []approval.Approval  // in creation order
	receipts  map[string]time.Time // used receipt ID -> its expiry
	usage     []policy.UsageRecord
	pins      map[pinKey]toolpin.Pin
	anchor    *audit.Anchor // where the log starts after archiving
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{receipts: map[string]time.Time{}, pins: map[pinKey]toolpin.Pin{}}
}

// Close implements Store.
func (m *Memory) Close() {}

// MarkReceiptUsed implements Store.
func (m *Memory) MarkReceiptUsed(_ context.Context, receiptID string, usedAt, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, used := m.receipts[receiptID]; used {
		return verify.ErrAlreadyUsed
	}
	m.receipts[receiptID] = expiresAt
	return nil
}

// PruneUsedReceipts implements Store.
func (m *Memory) PruneUsedReceipts(_ context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for id, exp := range m.receipts {
		if exp.Before(now) {
			delete(m.receipts, id) // deleting while ranging over a map is allowed in Go
			n++
		}
	}
	return n, nil
}

// AppendAudit implements Store.
func (m *Memory) AppendAudit(_ context.Context, e audit.Entry) (audit.Entry, error) {
	if e.ID == "" {
		id, err := newID("aud_")
		if err != nil {
			return audit.Entry{}, err
		}
		e.ID = id
	}
	m.mu.Lock()
	defer m.mu.Unlock() // defer runs when the function returns, so the lock is always released
	prev, seq := m.lastLocked()
	e, err := audit.Chain(prev, e)
	if err != nil {
		return audit.Entry{}, err
	}
	e.Seq = seq + 1
	m.audit = append(m.audit, e)
	return e, nil
}

// lastLocked returns the hash and seq the next entry follows: the newest
// entry's, or the anchor's once every entry was archived. Callers hold m.mu.
func (m *Memory) lastLocked() (hash string, seq int64) {
	if n := len(m.audit); n > 0 {
		return m.audit[n-1].Hash, m.audit[n-1].Seq
	}
	if m.anchor != nil {
		return m.anchor.Hash, m.anchor.Seq
	}
	return "", 0
}

// AuditAnchor implements audit.AnchorSource.
func (m *Memory) AuditAnchor(context.Context) (audit.Anchor, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.anchor == nil {
		return audit.Anchor{}, false, nil
	}
	return *m.anchor, true, nil
}

// ArchiveAudit implements Store.
func (m *Memory) ArchiveAudit(_ context.Context, a audit.Anchor) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkArchiveLocked(a); err != nil {
		return 0, err
	}
	return m.archiveLocked(a), nil
}

// checkArchiveLocked checks a may become the anchor: it names an entry
// in the log, by its hash, after the anchor there is now.
func (m *Memory) checkArchiveLocked(a audit.Anchor) error {
	if m.anchor != nil && a.Seq <= m.anchor.Seq {
		return fmt.Errorf("store: entry %d is already archived", a.Seq)
	}
	for _, e := range m.audit {
		if e.Seq == a.Seq {
			if e.Hash == "" || e.Hash != a.Hash {
				return fmt.Errorf("store: entry %d's hash isn't %s", a.Seq, a.Hash)
			}
			return nil
		}
	}
	return fmt.Errorf("store: there is no entry %d to archive up to", a.Seq)
}

// archiveLocked deletes the entries through a.Seq and sets the anchor,
// with no checks: replaying the journal uses it as well.
func (m *Memory) archiveLocked(a audit.Anchor) int64 {
	kept := m.audit[:0]
	for _, e := range m.audit {
		if e.Seq > a.Seq {
			kept = append(kept, e)
		}
	}
	n := int64(len(m.audit) - len(kept))
	// Clear the tail, so the deleted entries don't linger in the backing array.
	clear(m.audit[len(kept):])
	m.audit = kept
	m.anchor = &a
	return n
}

// ForEachAudit implements audit.Walker. It works on a copy, so fn may take
// its time without holding up appends.
func (m *Memory) ForEachAudit(_ context.Context, fn func(audit.Entry) error) error {
	m.mu.Lock()
	entries := append([]audit.Entry(nil), m.audit...)
	m.mu.Unlock()
	for _, e := range entries {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// LastAudit implements Store.
func (m *Memory) LastAudit(context.Context) (audit.Entry, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.audit) == 0 {
		return audit.Entry{}, false, nil
	}
	return m.audit[len(m.audit)-1], true, nil
}

// ListAudit implements Store.
func (m *Memory) ListAudit(_ context.Context, f audit.Filter) ([]audit.Entry, error) {
	limit := f.EffectiveLimit()
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []audit.Entry
	for i := len(m.audit) - 1; i >= 0 && len(out) < limit; i-- { // walk backwards: newest first
		if f.Matches(m.audit[i]) {
			out = append(out, m.audit[i])
		}
	}
	return out, nil
}

// newID returns prefix plus 16 random hex characters, e.g. "aud_3f9a0c...".
func newID(prefix string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

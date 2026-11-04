// Package store holds ConsequenceOS state behind one interface, with an
// in-memory implementation and a Postgres one.
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
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
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{receipts: map[string]time.Time{}}
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
	prev := ""
	if n := len(m.audit); n > 0 {
		prev = m.audit[n-1].Hash
	}
	e, err := audit.Chain(prev, e)
	if err != nil {
		return audit.Entry{}, err
	}
	e.Seq = int64(len(m.audit) + 1)
	m.audit = append(m.audit, e)
	return e, nil
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

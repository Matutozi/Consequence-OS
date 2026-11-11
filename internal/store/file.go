package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
)

// Names inside a state_dir.
const (
	journalName = "journal.jsonl"
	lockName    = "lock"
)

// DefaultLockTimeout is how long OpenFile waits for another process to
// close the same state_dir.
const DefaultLockTimeout = 2 * time.Second

// compactMin is the journal size below which it is never compacted.
const compactMin = 1 << 20 // 1 MiB

var (
	// ErrLocked means another process has the state_dir open.
	ErrLocked = errors.New("store: another process is using this state_dir")
	// ErrReadOnly is returned by every change to a store opened read-only.
	ErrReadOnly = errors.New("store: opened read-only")
)

// FileOptions configures OpenFile.
type FileOptions struct {
	// Log reports a torn last line dropped on open. nil discards.
	Log *slog.Logger
	// ReadOnly loads the journal without taking the lock or changing
	// anything, so the audit log can be checked while a server runs. Every
	// change returns ErrReadOnly.
	ReadOnly bool
	// LockTimeout is how long to wait for another process's lock; 0 means
	// DefaultLockTimeout.
	LockTimeout time.Duration
}

// File is a Store for one machine that needs no database. It is the
// in-memory store plus a journal, state_dir/journal.jsonl: every change is
// one JSON line, written and synced to disk before the change is reported
// done, and the journal is replayed on open. So the audit log, limits,
// approvals and used receipts all survive a restart.
//
// One process at a time: OpenFile takes an exclusive lock on
// state_dir/lock and holds it until Close. The kernel frees the lock if the
// process dies, so a crash never leaves it stuck.
//
// When the journal has doubled since it was last compacted, and is at
// least 1 MiB, it is rewritten from the current state: every audit entry is
// kept unchanged, and pruned usage, expired receipts and the steps of each
// approval collapse into one line each.
//
// The journal holds what the other stores hold and nothing more: argument
// hashes and summaries, and an approval's arguments for its approver.
type File struct {
	mem      *Memory
	dir      string
	log      *slog.Logger
	readOnly bool

	mu      sync.Mutex // serializes changes, so the journal's order is the memory's
	journal *os.File   // nil when read-only
	lock    *os.File   // nil when read-only
	size    int64      // bytes in the journal
	base    int64      // its size after opening or the last compaction
	// minCompact is compactMin; tests lower it.
	minCompact int64
	broken     atomic.Pointer[error]
	closed     bool
}

// OpenFile opens the file store in dir, creating dir (mode 0700) and the
// journal (0600) if needed. It fails if another process has dir open and
// doesn't close it within the lock timeout.
func OpenFile(dir string, opts FileOptions) (*File, error) {
	f := &File{mem: NewMemory(), dir: dir, log: opts.Log, readOnly: opts.ReadOnly, minCompact: compactMin}
	if f.log == nil {
		f.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	path := filepath.Join(dir, journalName)
	if opts.ReadOnly {
		j, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			return f, nil // nothing recorded yet
		}
		if err != nil {
			return nil, fmt.Errorf("store: open journal: %w", err)
		}
		defer j.Close()
		if _, _, err := f.replay(j, path); err != nil {
			return nil, err
		}
		return f, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create state_dir: %w", err)
	}
	timeout := opts.LockTimeout
	if timeout <= 0 {
		timeout = DefaultLockTimeout
	}
	lock, err := lockFile(filepath.Join(dir, lockName), timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %s (waited %s)", err, dir, timeout)
	}
	f.lock = lock
	_, statErr := os.Stat(path)
	j, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("store: open journal: %w", err)
	}
	f.journal = j
	if errors.Is(statErr, os.ErrNotExist) {
		_ = syncDir(dir) // make the new file's name durable too
	}
	good, torn, err := f.replay(j, path)
	if err != nil {
		f.Close()
		return nil, err
	}
	if torn {
		// Cut the torn line off, so the next change starts on a line of its own.
		if err := j.Truncate(good); err != nil {
			f.Close()
			return nil, fmt.Errorf("store: drop torn journal line: %w", err)
		}
	}
	f.size, f.base = good, good
	return f, nil
}

// Close releases the journal and the lock. It is safe to call more than once.
func (f *File) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	if f.journal != nil {
		_ = f.journal.Close()
	}
	if f.lock != nil {
		_ = f.lock.Close() // closing the file frees the lock
	}
}

// Dir returns the state_dir the store was opened on.
func (f *File) Dir() string { return f.dir }

// check fails every operation once a journal write has failed: memory may
// then hold a change the journal doesn't, and nothing should act on it.
func (f *File) check() error {
	if p := f.broken.Load(); p != nil {
		return *p
	}
	return nil
}

// write applies one change to memory and journals it. change returns the
// line to journal, or nil when nothing changed. A change that fails leaves
// memory as it was, so nothing is journaled.
//
// Between the change and its line reaching disk, other goroutines may read
// it. If the write then fails, the store refuses everything from then on,
// and a restart goes back to what the journal holds.
func (f *File) write(change func() (*record, error)) error {
	if f.readOnly {
		return ErrReadOnly
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errors.New("store: file store is closed")
	}
	if err := f.check(); err != nil {
		return err
	}
	rec, err := change()
	if err != nil || rec == nil {
		return err
	}
	if err := f.append(rec); err != nil {
		e := fmt.Errorf("store: journal write failed, so the file store refuses every request until a restart: %w", err)
		f.broken.Store(&e)
		return e
	}
	if f.size >= f.minCompact && f.size >= 2*f.base {
		f.compact()
	}
	return nil
}

// append writes one line and syncs it to disk. Callers hold f.mu.
func (f *File) append(rec *record) error {
	line, err := encodeRecord(rec)
	if err != nil {
		return err
	}
	n, err := f.journal.Write(line)
	f.size += int64(n)
	if err != nil {
		return err
	}
	return f.journal.Sync()
}

// MarkReceiptUsed implements Store.
func (f *File) MarkReceiptUsed(ctx context.Context, receiptID string, usedAt, expiresAt time.Time) error {
	return f.write(func() (*record, error) {
		if err := f.mem.MarkReceiptUsed(ctx, receiptID, usedAt, expiresAt); err != nil {
			return nil, err
		}
		return &record{Op: opReceipt, ID: receiptID, At: usedAt, Until: expiresAt}, nil
	})
}

// PruneUsedReceipts implements Store.
func (f *File) PruneUsedReceipts(ctx context.Context, now time.Time) (int64, error) {
	var n int64
	err := f.write(func() (*record, error) {
		var err error
		if n, err = f.mem.PruneUsedReceipts(ctx, now); err != nil || n == 0 {
			return nil, err
		}
		return &record{Op: opPruneReceipts, At: now}, nil
	})
	return n, err
}

// AppendAudit implements Store.
func (f *File) AppendAudit(ctx context.Context, e audit.Entry) (audit.Entry, error) {
	var saved audit.Entry
	err := f.write(func() (*record, error) {
		var err error
		if saved, err = f.mem.AppendAudit(ctx, e); err != nil {
			return nil, err
		}
		return &record{Op: opAudit, Audit: &saved}, nil
	})
	if err != nil {
		return audit.Entry{}, err
	}
	return saved, nil
}

// ListAudit implements Store.
func (f *File) ListAudit(ctx context.Context, filter audit.Filter) ([]audit.Entry, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	return f.mem.ListAudit(ctx, filter)
}

// ForEachAudit implements audit.Walker.
func (f *File) ForEachAudit(ctx context.Context, fn func(audit.Entry) error) error {
	if err := f.check(); err != nil {
		return err
	}
	return f.mem.ForEachAudit(ctx, fn)
}

// LastAudit implements Store.
func (f *File) LastAudit(ctx context.Context) (audit.Entry, bool, error) {
	if err := f.check(); err != nil {
		return audit.Entry{}, false, err
	}
	return f.mem.LastAudit(ctx)
}

// CreateApproval implements approval.Repository.
func (f *File) CreateApproval(ctx context.Context, a approval.Approval) error {
	return f.write(func() (*record, error) {
		if err := f.mem.CreateApproval(ctx, a); err != nil {
			return nil, err
		}
		return &record{Op: opApproval, Approval: newApprovalRecord(a)}, nil
	})
}

// GetApproval implements approval.Repository.
func (f *File) GetApproval(ctx context.Context, id string) (approval.Approval, error) {
	if err := f.check(); err != nil {
		return approval.Approval{}, err
	}
	return f.mem.GetApproval(ctx, id)
}

// FindLatestApproval implements approval.Repository.
func (f *File) FindLatestApproval(ctx context.Context, agentID, tool, paramsHash string) (approval.Approval, error) {
	if err := f.check(); err != nil {
		return approval.Approval{}, err
	}
	return f.mem.FindLatestApproval(ctx, agentID, tool, paramsHash)
}

// DecideApproval implements approval.Repository.
func (f *File) DecideApproval(ctx context.Context, id string, status approval.Status, by string, at, validUntil time.Time) (approval.Approval, error) {
	var a approval.Approval
	err := f.write(func() (*record, error) {
		var err error
		if a, err = f.mem.DecideApproval(ctx, id, status, by, at, validUntil); err != nil {
			return nil, err
		}
		return &record{Op: opDecide, ID: id, Status: status, By: by, At: at, Until: validUntil}, nil
	})
	if err != nil {
		return approval.Approval{}, err
	}
	return a, nil
}

// UseApproval implements approval.Repository.
func (f *File) UseApproval(ctx context.Context, id string, at time.Time) (approval.Approval, error) {
	var a approval.Approval
	err := f.write(func() (*record, error) {
		var err error
		if a, err = f.mem.UseApproval(ctx, id, at); err != nil {
			return nil, err
		}
		return &record{Op: opUse, ID: id, At: at}, nil
	})
	if err != nil {
		return approval.Approval{}, err
	}
	return a, nil
}

// CountPendingApprovals implements approval.Repository.
func (f *File) CountPendingApprovals(ctx context.Context, agentID string, now time.Time) (int, error) {
	if err := f.check(); err != nil {
		return 0, err
	}
	return f.mem.CountPendingApprovals(ctx, agentID, now)
}

// ExpireApprovals implements approval.Repository.
func (f *File) ExpireApprovals(ctx context.Context, now time.Time) ([]approval.Approval, error) {
	var expired []approval.Approval
	err := f.write(func() (*record, error) {
		var err error
		if expired, err = f.mem.ExpireApprovals(ctx, now); err != nil || len(expired) == 0 {
			return nil, err
		}
		return &record{Op: opExpire, At: now}, nil
	})
	if err != nil {
		return nil, err
	}
	return expired, nil
}

// RecordUsage implements Store.
func (f *File) RecordUsage(ctx context.Context, u policy.UsageRecord) error {
	return f.write(func() (*record, error) {
		if err := f.mem.RecordUsage(ctx, u); err != nil {
			return nil, err
		}
		return &record{Op: opUsage, Usage: newUsageRecord(u)}, nil
	})
}

// CountUsage implements policy.UsageCounter.
func (f *File) CountUsage(ctx context.Context, agentID, scope string, since time.Time, sumArg string) (int, float64, error) {
	if err := f.check(); err != nil {
		return 0, 0, err
	}
	return f.mem.CountUsage(ctx, agentID, scope, since, sumArg)
}

// PruneUsage implements Store.
func (f *File) PruneUsage(ctx context.Context, before time.Time) (int64, error) {
	var n int64
	err := f.write(func() (*record, error) {
		var err error
		if n, err = f.mem.PruneUsage(ctx, before); err != nil || n == 0 {
			return nil, err
		}
		return &record{Op: opPruneUsage, At: before}, nil
	})
	return n, err
}

// syncDir syncs a directory, so a file created or renamed in it survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Compile-time check that *File is a Store.
var _ Store = (*File)(nil)

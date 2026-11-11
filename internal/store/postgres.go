package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// The //go:embed line compiles the SQL files into the binary, so the server
// needs no files on disk to migrate its database.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

// migrationLock is an arbitrary number shared by every consequenced process,
// so only one of them migrates at a time.
const migrationLock = 7_461_002

// auditChainLock serializes audit appends across every process sharing the
// database, so each entry links to the true previous one and the chain never forks.
const auditChainLock = 7_461_003

// Postgres is a Store backed by PostgreSQL.
type Postgres struct {
	pool *pgxpool.Pool
}

// OpenPostgres connects and brings the schema up to date.
func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	p := &Postgres{pool: pool}
	if err := p.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return p, nil
}

// Close implements Store.
func (p *Postgres) Close() { p.pool.Close() }

// migrate applies each migrations/NNNN_name.sql that hasn't run yet, in
// order, each in its own transaction.
func (p *Postgres) migrate(ctx context.Context) error {
	names, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names) // 0001_, 0002_, ... sort into the order they must run

	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// Held until this transaction ends, so concurrent starts wait their turn.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLock); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version    integer     PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
			return err
		}
		for _, name := range names {
			version, err := strconv.Atoi(strings.SplitN(strings.TrimPrefix(name, "migrations/"), "_", 2)[0])
			if err != nil {
				return fmt.Errorf("migration %s: name must start with a number", name)
			}
			var done bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&done); err != nil {
				return err
			}
			if done {
				continue
			}
			sql, err := migrationFiles.ReadFile(name)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("migration %s: %w", name, err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
				return err
			}
		}
		return nil
	})
}

// --- audit ---

// AppendAudit implements Store.
func (p *Postgres) AppendAudit(ctx context.Context, e audit.Entry) (audit.Entry, error) {
	if e.ID == "" {
		id, err := newID("aud_")
		if err != nil {
			return audit.Entry{}, err
		}
		e.ID = id
	}
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// Held until the transaction ends: the read of the last hash and the
		// insert happen as one step for every server sharing the database.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditChainLock); err != nil {
			return err
		}
		var prev string
		err := tx.QueryRow(ctx, `SELECT hash FROM audit_entries ORDER BY seq DESC LIMIT 1`).Scan(&prev)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if e, err = audit.Chain(prev, e); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO audit_entries
			(id, time, agent_id, owner_id, tool, params_hash, summary, level, decision, rule, outcome,
			 approval_id, receipt_id, detail, prev_hash, hash, score)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) RETURNING seq`,
			e.ID, e.Time, e.AgentID, e.OwnerID, e.Tool, e.ParamsHash, e.Summary, string(e.Level), string(e.Decision),
			e.Rule, string(e.Outcome), e.ApprovalID, e.ReceiptID, e.Detail, e.PrevHash, e.Hash, e.Score).Scan(&e.Seq)
	})
	if err != nil {
		return audit.Entry{}, fmt.Errorf("postgres: append audit: %w", err)
	}
	return e, nil
}

const auditColumns = `seq, id, time, agent_id, owner_id, tool, params_hash, summary, level, decision, rule,
	outcome, approval_id, receipt_id, detail, prev_hash, hash, score`

func scanAudit(row pgx.Row) (audit.Entry, error) {
	var e audit.Entry
	var level, decision, outcome string
	err := row.Scan(&e.Seq, &e.ID, &e.Time, &e.AgentID, &e.OwnerID, &e.Tool, &e.ParamsHash, &e.Summary,
		&level, &decision, &e.Rule, &outcome, &e.ApprovalID, &e.ReceiptID, &e.Detail, &e.PrevHash, &e.Hash, &e.Score)
	if err != nil {
		return audit.Entry{}, err
	}
	e.Time = e.Time.UTC()
	e.Level, e.Decision, e.Outcome = policy.Level(level), policy.Action(decision), audit.Outcome(outcome)
	return e, nil
}

// ForEachAudit implements audit.Walker, reading the log in order without
// loading it all into memory.
func (p *Postgres) ForEachAudit(ctx context.Context, fn func(audit.Entry) error) error {
	rows, err := p.pool.Query(ctx, `SELECT `+auditColumns+` FROM audit_entries ORDER BY seq`)
	if err != nil {
		return fmt.Errorf("postgres: read audit: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// LastAudit implements Store.
func (p *Postgres) LastAudit(ctx context.Context) (audit.Entry, bool, error) {
	e, err := scanAudit(p.pool.QueryRow(ctx, `SELECT `+auditColumns+` FROM audit_entries ORDER BY seq DESC LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return audit.Entry{}, false, nil
	}
	if err != nil {
		return audit.Entry{}, false, fmt.Errorf("postgres: last audit: %w", err)
	}
	return e, true, nil
}

// ListAudit implements Store. Filters become $n parameters, never pasted
// into the SQL text, so they can't inject SQL.
func (p *Postgres) ListAudit(ctx context.Context, f audit.Filter) ([]audit.Entry, error) {
	var where []string
	var args []any
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if f.AgentID != "" {
		add("agent_id = $%d", f.AgentID)
	}
	if f.Tool != "" {
		add("tool = $%d", f.Tool)
	}
	if f.Decision != "" {
		add("decision = $%d", string(f.Decision))
	}
	if !f.Since.IsZero() {
		add("time >= $%d", f.Since)
	}
	if !f.Until.IsZero() {
		add("time < $%d", f.Until)
	}

	query := `SELECT ` + auditColumns + ` FROM audit_entries`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, f.EffectiveLimit())
	query += fmt.Sprintf(" ORDER BY time DESC, seq DESC LIMIT $%d", len(args))

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list audit: %w", err)
	}
	defer rows.Close()

	var out []audit.Entry
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- approvals ---

const approvalColumns = `id, agent_id, owner_id, tool, params_hash, summary, arguments, level, rule,
	status, created_at, decided_at, decided_by, valid_until, used_at, expires_at, score, reasons`

// CreateApproval implements approval.Repository.
func (p *Postgres) CreateApproval(ctx context.Context, a approval.Approval) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO approvals
			(id, agent_id, owner_id, tool, params_hash, summary, arguments, level, rule, status, created_at, expires_at,
			 score, reasons)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
			a.ID, a.AgentID, a.OwnerID, a.Tool, a.ParamsHash, a.Summary, string(a.Arguments),
			string(a.Level), a.Rule, string(a.Status), a.CreatedAt, nullTime(a.ExpiresAt), a.Score, reasonsJSON(a.Reasons))
		if err != nil {
			return fmt.Errorf("postgres: create approval: %w", err)
		}
		for _, t := range a.Tokens {
			if _, err := tx.Exec(ctx, `INSERT INTO approval_tokens (approval_id, approver, token_hash) VALUES ($1, $2, $3)`,
				a.ID, t.Approver, t.Hash[:]); err != nil {
				return fmt.Errorf("postgres: create approval token: %w", err)
			}
		}
		return nil
	})
}

// GetApproval implements approval.Repository.
func (p *Postgres) GetApproval(ctx context.Context, id string) (approval.Approval, error) {
	return p.scanApproval(ctx, p.pool.QueryRow(ctx, `SELECT `+approvalColumns+` FROM approvals WHERE id = $1`, id))
}

// FindLatestApproval implements approval.Repository.
func (p *Postgres) FindLatestApproval(ctx context.Context, agentID, tool, paramsHash string) (approval.Approval, error) {
	return p.scanApproval(ctx, p.pool.QueryRow(ctx, `SELECT `+approvalColumns+` FROM approvals
		WHERE agent_id = $1 AND tool = $2 AND params_hash = $3 ORDER BY seq DESC LIMIT 1`, agentID, tool, paramsHash))
}

// DecideApproval implements approval.Repository. The WHERE status = 'pending'
// makes check-and-update one atomic statement.
func (p *Postgres) DecideApproval(ctx context.Context, id string, status approval.Status, by string, at, validUntil time.Time) (approval.Approval, error) {
	a, err := p.scanApproval(ctx, p.pool.QueryRow(ctx, `UPDATE approvals
		SET status = $2, decided_by = $3, decided_at = $4, valid_until = $5
		WHERE id = $1 AND status = 'pending' AND (expires_at IS NULL OR expires_at > $4)
		RETURNING `+approvalColumns,
		id, string(status), by, at, nullTime(validUntil)))
	if errors.Is(err, approval.ErrNotFound) {
		return approval.Approval{}, p.whyNoRow(ctx, id, approval.ErrNotPending)
	}
	return a, err
}

// UseApproval implements approval.Repository, atomically for the same reason.
func (p *Postgres) UseApproval(ctx context.Context, id string, at time.Time) (approval.Approval, error) {
	a, err := p.scanApproval(ctx, p.pool.QueryRow(ctx, `UPDATE approvals SET status = 'used', used_at = $2
		WHERE id = $1 AND status = 'approved' AND valid_until > $2 RETURNING `+approvalColumns, id, at))
	if errors.Is(err, approval.ErrNotFound) {
		return approval.Approval{}, p.whyNoRow(ctx, id, approval.ErrNotUsable)
	}
	return a, err
}

// CountPendingApprovals implements approval.Repository. The approvals_lookup
// index starts with agent_id, so this reads only this agent's rows.
func (p *Postgres) CountPendingApprovals(ctx context.Context, agentID string, now time.Time) (int, error) {
	var n int
	err := p.pool.QueryRow(ctx, `SELECT count(*) FROM approvals
		WHERE agent_id = $1 AND status = 'pending' AND (expires_at IS NULL OR expires_at > $2)`,
		agentID, now).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("postgres: count pending approvals: %w", err)
	}
	return n, nil
}

// ExpireApprovals implements approval.Repository. One UPDATE both finds and
// changes the rows, so two servers can't both expire the same approval.
func (p *Postgres) ExpireApprovals(ctx context.Context, now time.Time) ([]approval.Approval, error) {
	rows, err := p.pool.Query(ctx, `UPDATE approvals SET status = 'expired'
		WHERE status = 'pending' AND expires_at <= $1 RETURNING id`, now)
	if err != nil {
		return nil, fmt.Errorf("postgres: expire approvals: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("postgres: expire approvals: %w", err)
	}
	expired := make([]approval.Approval, 0, len(ids))
	for _, id := range ids {
		a, err := p.GetApproval(ctx, id)
		if err != nil {
			return nil, err
		}
		expired = append(expired, a)
	}
	return expired, nil
}

// whyNoRow tells "doesn't exist" apart from "exists but in the wrong state".
func (p *Postgres) whyNoRow(ctx context.Context, id string, wrongState error) error {
	var exists bool
	if err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM approvals WHERE id = $1)`, id).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return wrongState
	}
	return approval.ErrNotFound
}

func (p *Postgres) scanApproval(ctx context.Context, row pgx.Row) (approval.Approval, error) {
	var a approval.Approval
	var args, level, status string
	var decidedAt, validUntil, usedAt, expiresAt *time.Time // pointers, because these columns can be NULL
	var reasons []byte
	err := row.Scan(&a.ID, &a.AgentID, &a.OwnerID, &a.Tool, &a.ParamsHash, &a.Summary, &args, &level, &a.Rule,
		&status, &a.CreatedAt, &decidedAt, &a.DecidedBy, &validUntil, &usedAt, &expiresAt, &a.Score, &reasons)
	if errors.Is(err, pgx.ErrNoRows) {
		return approval.Approval{}, approval.ErrNotFound
	}
	if err != nil {
		return approval.Approval{}, fmt.Errorf("postgres: read approval: %w", err)
	}
	a.Arguments, a.Level, a.Status = []byte(args), policy.Level(level), approval.Status(status)
	if err := json.Unmarshal(reasons, &a.Reasons); err != nil {
		return approval.Approval{}, fmt.Errorf("postgres: read approval reasons: %w", err)
	}
	a.CreatedAt = a.CreatedAt.UTC()
	a.DecidedAt, a.ValidUntil, a.UsedAt, a.ExpiresAt = utc(decidedAt), utc(validUntil), utc(usedAt), utc(expiresAt)

	rows, err := p.pool.Query(ctx, `SELECT approver, token_hash FROM approval_tokens WHERE approval_id = $1 ORDER BY approver`, a.ID)
	if err != nil {
		return approval.Approval{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var t approval.ApproverToken
		var hash []byte
		if err := rows.Scan(&t.Approver, &hash); err != nil {
			return approval.Approval{}, err
		}
		copy(t.Hash[:], hash)
		a.Tokens = append(a.Tokens, t)
	}
	return a, rows.Err()
}

// --- receipts ---

// MarkReceiptUsed implements Store. The primary key makes the insert
// succeed exactly once per receipt ID, even across many servers.
func (p *Postgres) MarkReceiptUsed(ctx context.Context, receiptID string, usedAt, expiresAt time.Time) error {
	tag, err := p.pool.Exec(ctx, `INSERT INTO used_receipts (receipt_id, used_at, expires_at) VALUES ($1, $2, $3)
		ON CONFLICT (receipt_id) DO NOTHING`, receiptID, usedAt, expiresAt)
	if err != nil {
		return fmt.Errorf("postgres: mark receipt used: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return verify.ErrAlreadyUsed
	}
	return nil
}

// PruneUsedReceipts implements Store. Safe to run at any time, from any server.
func (p *Postgres) PruneUsedReceipts(ctx context.Context, now time.Time) (int64, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM used_receipts WHERE expires_at < $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// reasonsJSON stores reasons as a JSON array; none is [] rather than NULL.
func reasonsJSON(reasons []string) string {
	if len(reasons) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(reasons) // a []string always encodes
	return string(b)
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil // stored as NULL
	}
	return t
}

func utc(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

// Compile-time checks that both stores satisfy Store.
var (
	_ Store = (*Postgres)(nil)
	_ Store = (*Memory)(nil)
)

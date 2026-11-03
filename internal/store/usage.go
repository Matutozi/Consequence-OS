package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/matutozi/consequence-os/internal/policy"
)

// RecordUsage implements Store.
func (m *Memory) RecordUsage(_ context.Context, u policy.UsageRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.usage = append(m.usage, u)
	return nil
}

// CountUsage implements policy.UsageCounter.
func (m *Memory) CountUsage(_ context.Context, agentID, tool string, since time.Time, sumArg string) (int, float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count, sum := 0, 0.0
	for _, u := range m.usage {
		if u.AgentID == agentID && u.Tool == tool && u.At.After(since) {
			count++
			sum += u.Values[sumArg] // a missing key reads as 0
		}
	}
	return count, sum, nil
}

// PruneUsage implements Store.
func (m *Memory) PruneUsage(_ context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.usage[:0] // reuse the backing array: filter in place
	for _, u := range m.usage {
		if !u.At.Before(before) {
			kept = append(kept, u)
		}
	}
	n := int64(len(m.usage) - len(kept))
	m.usage = kept
	return n, nil
}

// RecordUsage implements Store: the call row and its values in one transaction.
func (p *Postgres) RecordUsage(ctx context.Context, u policy.UsageRecord) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		const insert = `INSERT INTO usage_records (agent_id, tool, at, arg, value) VALUES ($1, $2, $3, $4, $5)`
		if _, err := tx.Exec(ctx, insert, u.AgentID, u.Tool, u.At, "", 0); err != nil {
			return fmt.Errorf("postgres: record usage: %w", err)
		}
		for arg, v := range u.Values {
			if _, err := tx.Exec(ctx, insert, u.AgentID, u.Tool, u.At, arg, v); err != nil {
				return fmt.Errorf("postgres: record usage: %w", err)
			}
		}
		return nil
	})
}

// CountUsage implements policy.UsageCounter.
func (p *Postgres) CountUsage(ctx context.Context, agentID, tool string, since time.Time, sumArg string) (int, float64, error) {
	var count int
	var sum float64
	err := p.pool.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE arg = ''),
			coalesce(sum(value) FILTER (WHERE arg = $4 AND $4 <> ''), 0)
		FROM usage_records
		WHERE agent_id = $1 AND tool = $2 AND at > $3 AND (arg = '' OR arg = $4)`,
		agentID, tool, since, sumArg).Scan(&count, &sum)
	if err != nil {
		return 0, 0, fmt.Errorf("postgres: count usage: %w", err)
	}
	return count, sum, nil
}

// PruneUsage implements Store.
func (p *Postgres) PruneUsage(ctx context.Context, before time.Time) (int64, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM usage_records WHERE at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("postgres: prune usage: %w", err)
	}
	return tag.RowsAffected(), nil
}

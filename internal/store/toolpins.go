package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/matutozi/consequence-os/internal/toolpin"
)

// Pins of tool definitions, for toolpin.Repository. A pin is small and
// changes rarely: when a tool is first listed, when its definition
// changes, and when a person accepts the change.

// pinKey is the key of a pin in Memory. A struct rather than the two
// joined into one string, so no server name can run into a tool name.
type pinKey struct{ server, tool string }

// ToolPin implements toolpin.Repository.
func (m *Memory) ToolPin(_ context.Context, server, tool string) (toolpin.Pin, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pins[pinKey{server, tool}]
	return p, ok, nil
}

// ListToolPins implements toolpin.Repository.
func (m *Memory) ListToolPins(_ context.Context, server string) ([]toolpin.Pin, error) {
	m.mu.Lock()
	out := make([]toolpin.Pin, 0, len(m.pins))
	for k, p := range m.pins {
		if server == "" || k.server == server {
			out = append(out, p)
		}
	}
	m.mu.Unlock()
	sortPins(out)
	return out, nil
}

// UpdateToolPin implements toolpin.Repository. update runs under the
// store's lock, so nothing else changes the pin meanwhile.
func (m *Memory) UpdateToolPin(_ context.Context, server, tool string, update func(toolpin.Pin, bool) (toolpin.Pin, bool, error)) (toolpin.Pin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.updatePinLocked(server, tool, update)
}

func (m *Memory) updatePinLocked(server, tool string, update func(toolpin.Pin, bool) (toolpin.Pin, bool, error)) (toolpin.Pin, error) {
	k := pinKey{server, tool}
	old, ok := m.pins[k]
	next, save, err := update(old, ok)
	if err != nil {
		return toolpin.Pin{}, err
	}
	if !save {
		return old, nil
	}
	if next.Server != server || next.Tool != tool {
		return toolpin.Pin{}, errors.New("store: an update may not move a pin to another server or tool")
	}
	m.pins[k] = next
	return next, nil
}

func sortPins(pins []toolpin.Pin) {
	sort.Slice(pins, func(i, j int) bool {
		if pins[i].Server != pins[j].Server {
			return pins[i].Server < pins[j].Server
		}
		return pins[i].Tool < pins[j].Tool
	})
}

// ToolPin implements toolpin.Repository.
func (f *File) ToolPin(ctx context.Context, server, tool string) (toolpin.Pin, bool, error) {
	if err := f.check(); err != nil {
		return toolpin.Pin{}, false, err
	}
	return f.mem.ToolPin(ctx, server, tool)
}

// ListToolPins implements toolpin.Repository.
func (f *File) ListToolPins(ctx context.Context, server string) ([]toolpin.Pin, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	return f.mem.ListToolPins(ctx, server)
}

// UpdateToolPin implements toolpin.Repository. A saved pin is journaled
// whole, so replaying the line sets it.
func (f *File) UpdateToolPin(ctx context.Context, server, tool string, update func(toolpin.Pin, bool) (toolpin.Pin, bool, error)) (toolpin.Pin, error) {
	var out toolpin.Pin
	err := f.write(func() (*record, error) {
		saved := false
		var err error
		out, err = f.mem.UpdateToolPin(ctx, server, tool, func(old toolpin.Pin, ok bool) (toolpin.Pin, bool, error) {
			next, save, err := update(old, ok)
			saved = save && err == nil
			return next, save, err
		})
		if err != nil || !saved {
			return nil, err
		}
		return &record{Op: opToolPin, Pin: &out}, nil
	})
	if err != nil {
		return toolpin.Pin{}, err
	}
	return out, nil
}

// pinLock is the advisory lock key UpdateToolPin takes, with a hash of the
// server and tool, so two processes can't both create the same pin.
const pinLock = 7_461_004

// ToolPin implements toolpin.Repository.
func (p *Postgres) ToolPin(ctx context.Context, server, tool string) (toolpin.Pin, bool, error) {
	pin, err := scanPin(p.pool.QueryRow(ctx, `SELECT `+pinColumns+` FROM tool_pins WHERE server = $1 AND tool = $2`, server, tool))
	if errors.Is(err, pgx.ErrNoRows) {
		return toolpin.Pin{}, false, nil
	}
	if err != nil {
		return toolpin.Pin{}, false, fmt.Errorf("postgres: tool pin: %w", err)
	}
	return pin, true, nil
}

// ListToolPins implements toolpin.Repository.
func (p *Postgres) ListToolPins(ctx context.Context, server string) ([]toolpin.Pin, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+pinColumns+` FROM tool_pins WHERE $1 = '' OR server = $1 ORDER BY server, tool`, server)
	if err != nil {
		return nil, fmt.Errorf("postgres: list tool pins: %w", err)
	}
	defer rows.Close()
	var out []toolpin.Pin
	for rows.Next() {
		pin, err := scanPin(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: list tool pins: %w", err)
		}
		out = append(out, pin)
	}
	return out, rows.Err()
}

// UpdateToolPin implements toolpin.Repository, in one transaction that
// holds a lock on this server's tool, so it works even when there is no
// row yet to lock.
func (p *Postgres) UpdateToolPin(ctx context.Context, server, tool string, update func(toolpin.Pin, bool) (toolpin.Pin, bool, error)) (toolpin.Pin, error) {
	var out toolpin.Pin
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2 || ' ' || $3))`, pinLock, server, tool); err != nil {
			return err
		}
		old, err := scanPin(tx.QueryRow(ctx, `SELECT `+pinColumns+` FROM tool_pins WHERE server = $1 AND tool = $2`, server, tool))
		ok := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		next, save, err := update(old, ok)
		if err != nil {
			return err
		}
		if !save {
			out = old
			return nil
		}
		if next.Server != server || next.Tool != tool {
			return errors.New("store: an update may not move a pin to another server or tool")
		}
		_, err = tx.Exec(ctx, `INSERT INTO tool_pins (`+pinColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (server, tool) DO UPDATE SET hash = $3, definition = $4, pinned_at = $5, accepted_by = $6,
				seen = $7, seen_definition = $8, seen_at = $9`,
			next.Server, next.Tool, next.Hash, string(next.Definition), next.PinnedAt, next.AcceptedBy,
			next.Seen, string(next.SeenDefinition), nullTime(next.SeenAt))
		out = next
		return err
	})
	if err != nil {
		return toolpin.Pin{}, fmt.Errorf("postgres: update tool pin: %w", err)
	}
	return out, nil
}

const pinColumns = `server, tool, hash, definition, pinned_at, accepted_by, seen, seen_definition, seen_at`

func scanPin(row pgx.Row) (toolpin.Pin, error) {
	var pin toolpin.Pin
	var def, seenDef string
	var seenAt *time.Time
	if err := row.Scan(&pin.Server, &pin.Tool, &pin.Hash, &def, &pin.PinnedAt, &pin.AcceptedBy, &pin.Seen, &seenDef, &seenAt); err != nil {
		return toolpin.Pin{}, err
	}
	pin.PinnedAt = pin.PinnedAt.UTC()
	pin.Definition = []byte(def)
	if seenDef != "" {
		pin.SeenDefinition = []byte(seenDef)
	}
	pin.SeenAt = utc(seenAt)
	return pin, nil
}

// Compile-time checks that every store keeps pins.
var (
	_ toolpin.Repository = (*Memory)(nil)
	_ toolpin.Repository = (*File)(nil)
	_ toolpin.Repository = (*Postgres)(nil)
)

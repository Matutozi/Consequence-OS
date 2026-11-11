package store

import (
	"context"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
)

// CreateApproval implements approval.Repository.
func (m *Memory) CreateApproval(_ context.Context, a approval.Approval) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.approvals = append(m.approvals, a)
	return nil
}

// GetApproval implements approval.Repository.
func (m *Memory) GetApproval(_ context.Context, id string) (approval.Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i := m.indexOf(id); i >= 0 {
		return m.approvals[i], nil
	}
	return approval.Approval{}, approval.ErrNotFound
}

// FindLatestApproval implements approval.Repository.
func (m *Memory) FindLatestApproval(_ context.Context, agentID, tool, paramsHash string) (approval.Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.approvals) - 1; i >= 0; i-- {
		a := m.approvals[i]
		if a.AgentID == agentID && a.Tool == tool && a.ParamsHash == paramsHash {
			return a, nil
		}
	}
	return approval.Approval{}, approval.ErrNotFound
}

// DecideApproval implements approval.Repository. The check and the update
// happen under one lock, so two approvers can't both decide.
func (m *Memory) DecideApproval(_ context.Context, id string, status approval.Status, by string, at, validUntil time.Time) (approval.Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.indexOf(id)
	if i < 0 {
		return approval.Approval{}, approval.ErrNotFound
	}
	a := &m.approvals[i] // a pointer into the slice, so changes stick
	if a.Status != approval.StatusPending || a.Overdue(at) {
		return approval.Approval{}, approval.ErrNotPending
	}
	a.Status, a.DecidedBy, a.DecidedAt, a.ValidUntil = status, by, at, validUntil
	return *a, nil
}

// UseApproval implements approval.Repository. Atomic for the same reason.
func (m *Memory) UseApproval(_ context.Context, id string, at time.Time) (approval.Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.indexOf(id)
	if i < 0 {
		return approval.Approval{}, approval.ErrNotFound
	}
	a := &m.approvals[i]
	if a.Status != approval.StatusApproved || a.Expired(at) {
		return approval.Approval{}, approval.ErrNotUsable
	}
	a.Status, a.UsedAt = approval.StatusUsed, at
	return *a, nil
}

// CountPendingApprovals implements approval.Repository.
func (m *Memory) CountPendingApprovals(_ context.Context, agentID string, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, a := range m.approvals {
		if a.AgentID == agentID && a.Status == approval.StatusPending && !a.Overdue(now) {
			n++
		}
	}
	return n, nil
}

// ExpireApprovals implements approval.Repository.
func (m *Memory) ExpireApprovals(_ context.Context, now time.Time) ([]approval.Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var expired []approval.Approval
	for i := range m.approvals {
		if a := &m.approvals[i]; a.Overdue(now) {
			a.Status = approval.StatusExpired
			expired = append(expired, *a)
		}
	}
	return expired, nil
}

// indexOf finds an approval by ID. Callers must hold m.mu.
func (m *Memory) indexOf(id string) int {
	for i := range m.approvals {
		if m.approvals[i].ID == id {
			return i
		}
	}
	return -1
}

package approval_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/store"
)

// countingNotifier counts notices, safely across goroutines.
type countingNotifier struct {
	mu sync.Mutex
	n  int
}

func (c *countingNotifier) Notify(context.Context, approval.Notice) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
}

func (c *countingNotifier) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func cappedService(t *testing.T, max int) (*approval.Service, *countingNotifier, *time.Time) {
	t.Helper()
	clock := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	st := store.NewMemory()
	notes := &countingNotifier{}
	svc := approval.NewService(approval.Options{
		Repo: st, Audit: st, Validity: 10 * time.Minute, Timeout: time.Hour, MaxPending: max,
		Approvers: map[string][]string{"acme": {"ada@acme.example", "bo@acme.example"}},
		Notifier:  notes, Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		Now: func() time.Time { return clock },
	})
	return svc, notes, &clock
}

func TestTooManyPendingApprovals(t *testing.T) {
	ctx := context.Background()
	svc, notes, clock := cappedService(t, 20)

	for i := range 20 {
		if _, err := svc.Check(ctx, request(fmt.Sprint(5000+i))); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
	if got := notes.count(); got != 40 { // 20 approvals, 2 approvers each
		t.Fatalf("sent %d notices, want 40", got)
	}

	// The 21st distinct request is refused and nobody is emailed.
	if _, err := svc.Check(ctx, request("9999")); !errors.Is(err, approval.ErrTooManyPending) {
		t.Fatalf("21st request: err = %v, want ErrTooManyPending", err)
	}
	if got := notes.count(); got != 40 {
		t.Errorf("sent %d notices after the cap, want still 40", got)
	}

	// Asking again about one already waiting is fine: it opens nothing new.
	if res, err := svc.Check(ctx, request("5000")); err != nil || res.State != approval.StatePending {
		t.Errorf("retrying a pending request: %v, %v", res.State, err)
	}

	// Once the waiting ones are overdue they stop counting.
	*clock = clock.Add(time.Hour)
	if _, err := svc.Check(ctx, request("9999")); err != nil {
		t.Errorf("after the others expired: %v", err)
	}
}

func TestPendingCapHoldsUnderParallelRequests(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := cappedService(t, 5)

	var wg sync.WaitGroup
	var mu sync.Mutex
	opened, refused := 0, 0
	for i := range 30 {
		wg.Go(func() {
			_, err := svc.Check(ctx, request(fmt.Sprint(i)))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				opened++
			case errors.Is(err, approval.ErrTooManyPending):
				refused++
			default:
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if opened != 5 || refused != 25 {
		t.Errorf("opened %d, refused %d; want 5 and 25", opened, refused)
	}
}

func TestNoCapWhenMaxPendingIsZero(t *testing.T) {
	svc, _, _ := cappedService(t, 0)
	for i := range 50 {
		if _, err := svc.Check(context.Background(), request(fmt.Sprint(i))); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
}

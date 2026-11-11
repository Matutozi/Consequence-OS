package proxy

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/pkg/verify"
)

var approvalIDPattern = regexp.MustCompile(`apr_[0-9a-f]{16}`)

// approvalID pulls the approval ID out of a pending result's text.
func approvalID(t *testing.T, body string) string {
	t.Helper()
	id := approvalIDPattern.FindString(body)
	if id == "" {
		t.Fatalf("no approval ID in %s", body)
	}
	return id
}

// approveDirectly decides an approval the way a person with the approver
// link would. In stage 3 that link only appears in the server log, so the
// test reads the token from there too.
func approveDirectly(t *testing.T, f fixture, id string, approve bool) {
	t.Helper()
	m := regexp.MustCompile(`approvals/` + id + `\?token=([A-Za-z0-9_-]+)`).FindStringSubmatch(f.approvalLog.String())
	if m == nil {
		t.Fatalf("no approver link for %s in the log", id)
	}
	if _, err := f.approvals.Decide(context.Background(), id, m[1], approve); err != nil {
		t.Fatalf("Decide: %v", err)
	}
}

func mustHash(t *testing.T, args string) string {
	t.Helper()
	h, err := verify.ParamsHash([]byte(args))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestApprovalFlow(t *testing.T) {
	f := newFixture(t, nil)
	refund := call("payments.refund", `{"charge_id":"ch_1","amount":5000}`)

	// 1. First attempt is held and opens an approval.
	first := f.do(http.MethodPost, refund, nil).Body.String()
	if !strings.Contains(first, "Approval pending") || !strings.Contains(first, "http://cos.test/approvals/apr_") {
		t.Fatalf("first attempt: %s", first)
	}
	if strings.Contains(first, "token=") {
		t.Fatal("the agent must never receive the approver token")
	}
	id := approvalID(t, first)

	// 2. Retrying before anyone decides reuses the same approval.
	if again := approvalID(t, f.do(http.MethodPost, refund, nil).Body.String()); again != id {
		t.Fatalf("retry opened a new approval %s, want %s", again, id)
	}

	// 3. Different arguments are a different action and need their own approval.
	other := approvalID(t, f.do(http.MethodPost, call("payments.refund", `{"charge_id":"ch_1","amount":5001}`), nil).Body.String())
	if other == id {
		t.Fatal("different arguments reused the same approval")
	}
	if f.up.count() != 0 {
		t.Fatal("nothing should have been forwarded yet")
	}

	// 4. After approval, the retry goes through exactly once.
	approveDirectly(t, f, id, true)
	*f.clock = f.clock.Add(5 * time.Minute)
	if body := f.do(http.MethodPost, refund, nil).Body.String(); !strings.Contains(body, "from upstream") {
		t.Fatalf("approved retry was not forwarded: %s", body)
	}
	if f.up.count() != 1 {
		t.Fatalf("forwarded %d times, want 1", f.up.count())
	}

	// 5. A second retry needs a fresh approval: one yes is one call.
	next := f.do(http.MethodPost, refund, nil).Body.String()
	if !strings.Contains(next, "Approval pending") || approvalID(t, next) == id {
		t.Fatalf("second retry should open a new approval: %s", next)
	}
	if f.up.count() != 1 {
		t.Fatal("approval was used twice")
	}

	// The audit log tells the whole story, newest first, including the
	// approver's decision.
	entries, _ := f.store.ListAudit(context.Background(), audit.Filter{})
	var outcomes []string
	for _, e := range entries {
		outcomes = append(outcomes, string(e.Outcome))
	}
	if got, want := strings.Join(outcomes, ","), "held,forwarded,approved,held,held,held"; got != want {
		t.Errorf("audit outcomes = %s, want %s", got, want)
	}
}

func TestApprovalExpires(t *testing.T) {
	f := newFixture(t, nil)
	refund := call("payments.refund", `{"amount":5000}`)
	id := approvalID(t, f.do(http.MethodPost, refund, nil).Body.String())
	approveDirectly(t, f, id, true)

	*f.clock = f.clock.Add(10 * time.Minute) // exactly the validity window: too late
	body := f.do(http.MethodPost, refund, nil).Body.String()
	if !strings.Contains(body, "Approval pending") || approvalID(t, body) == id {
		t.Fatalf("expired approval should lead to a new request: %s", body)
	}
	if f.up.count() != 0 {
		t.Fatal("expired approval let the call through")
	}
}

func TestRejectedApproval(t *testing.T) {
	f := newFixture(t, nil)
	refund := call("payments.refund", `{"amount":5000}`)
	id := approvalID(t, f.do(http.MethodPost, refund, nil).Body.String())
	approveDirectly(t, f, id, false)

	body := f.do(http.MethodPost, refund, nil).Body.String()
	if !strings.Contains(body, "Rejected") || !strings.Contains(body, id) {
		t.Fatalf("retry after rejection: %s", body)
	}

	// Once the window passes, asking again is allowed.
	*f.clock = f.clock.Add(11 * time.Minute)
	if body := f.do(http.MethodPost, refund, nil).Body.String(); !strings.Contains(body, "Approval pending") {
		t.Fatalf("after the window a new approval should open: %s", body)
	}
	if f.up.count() != 0 {
		t.Fatal("rejected call reached upstream")
	}
}

func TestApprovalIsPerAgent(t *testing.T) {
	f := newFixture(t, nil)
	refund := call("payments.refund", `{"amount":5000}`)
	id := approvalID(t, f.do(http.MethodPost, refund, nil).Body.String())
	approveDirectly(t, f, id, true)

	// The same call from a different agent doesn't match the approval.
	res, err := f.approvals.Check(context.Background(), approval.Request{
		AgentID: "other-bot", OwnerID: "acme", Tool: "payments.refund", ParamsHash: mustHash(t, `{"amount":5000}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != approval.StatePending || res.Approval.ID == id {
		t.Errorf("another agent got state %v on approval %s", res.State, res.Approval.ID)
	}
}

func TestConcurrentRetriesUseApprovalOnce(t *testing.T) {
	f := newFixture(t, nil)
	refund := call("payments.refund", `{"amount":5000}`)
	id := approvalID(t, f.do(http.MethodPost, refund, nil).Body.String())
	approveDirectly(t, f, id, true)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.do(http.MethodPost, refund, nil)
		}()
	}
	wg.Wait()
	if f.up.count() != 1 {
		t.Errorf("forwarded %d times, want exactly 1", f.up.count())
	}
}

func TestTooManyPendingApprovalsAreRefused(t *testing.T) {
	f := newFixture(t, nil)
	refund := func(n int) string {
		return call("payments.refund", `{"charge_id":"ch_`+strconv.Itoa(n)+`","amount":5000}`)
	}
	for n := range f.approvals.MaxPending() {
		if body := f.do(http.MethodPost, refund(n), nil).Body.String(); !strings.Contains(body, "Approval pending") {
			t.Fatalf("call %d: %s", n+1, body)
		}
	}
	links := strings.Count(f.approvalLog.String(), "?token=")

	// One argument changed again: refused, not held, and nobody is notified.
	body := f.do(http.MethodPost, refund(999), nil).Body.String()
	if !strings.Contains(body, `"isError":true`) || !strings.Contains(body, "already has 20 requests waiting") || strings.Contains(body, "apr_") {
		t.Errorf("over the cap: %s", body)
	}
	if got := strings.Count(f.approvalLog.String(), "?token="); got != links {
		t.Errorf("approver links went from %d to %d, want no new ones", links, got)
	}
	if f.up.count() != 0 {
		t.Errorf("forwarded %d calls, want 0", f.up.count())
	}
	entries, _ := f.store.ListAudit(context.Background(), audit.Filter{Limit: 1})
	if e := entries[0]; e.Outcome != audit.OutcomeBlocked || e.Detail != "too many pending approvals" || e.Decision != "ask" {
		t.Errorf("audit entry = %+v, want blocked, too many pending approvals", e)
	}

	// Retrying one that is already waiting still gets the pending answer.
	if body := f.do(http.MethodPost, refund(0), nil).Body.String(); !strings.Contains(body, "Approval pending") {
		t.Errorf("retry of a waiting call: %s", body)
	}
}

package proxy

import (
	"testing"
	"time"
)

func TestLockAll(t *testing.T) {
	var k keyedLocks
	unlock := k.lockAll("bot\x00", []string{"payments.*", "payments.refund"})

	// A call sharing one scope has to wait for the first to finish.
	got := make(chan struct{})
	go func() {
		k.lockAll("bot\x00", []string{"payments.*"})() // blocks until the first call unlocks
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("a shared scope was locked twice at once")
	case <-time.After(20 * time.Millisecond):
	}

	unlock()
	unlock() // safe to call again
	<-got

	k.mu.Lock()
	n := len(k.locks)
	k.mu.Unlock()
	if n != 0 {
		t.Errorf("%d locks left behind, want 0", n)
	}
	k.lockAll("bot\x00", nil)() // no scopes: nothing to lock
}

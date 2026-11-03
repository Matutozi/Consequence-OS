package proxy

import "sync"

// keyedLocks hands out one mutex per key, e.g. per agent and tool, and
// forgets a key's mutex once nobody holds or waits for it.
//
// Limit rules use it: from the policy decision until the call is recorded,
// one agent's calls to one tool go one at a time, so two calls racing in
// parallel can't both slip under a limit. This works within one server;
// servers sharing a database can still overshoot by a call or two at once.
type keyedLocks struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

type keyedLock struct {
	mu      sync.Mutex
	waiters int // holders plus goroutines waiting; guarded by keyedLocks.mu
}

// lock blocks until key is free and returns the function that frees it.
// The returned function is safe to call more than once.
func (k *keyedLocks) lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*keyedLock{}
	}
	l := k.locks[key]
	if l == nil {
		l = &keyedLock{}
		k.locks[key] = l
	}
	l.waiters++
	k.mu.Unlock()

	l.mu.Lock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Unlock()
			k.mu.Lock()
			if l.waiters--; l.waiters == 0 {
				delete(k.locks, key)
			}
			k.mu.Unlock()
		})
	}
}

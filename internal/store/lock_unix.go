//go:build unix

package store

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// lockFile takes an exclusive flock on path, creating it if needed, and
// waits up to timeout for another process to let go. The lock lasts until
// the returned file is closed, or the process exits, however it exits.
func lockFile(path string, timeout time.Duration) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return f, nil
		case errors.Is(err, syscall.EINTR):
			continue
		case !errors.Is(err, syscall.EWOULDBLOCK):
			f.Close()
			return nil, err
		case time.Now().After(deadline):
			f.Close()
			return nil, ErrLocked
		}
		time.Sleep(20 * time.Millisecond)
	}
}

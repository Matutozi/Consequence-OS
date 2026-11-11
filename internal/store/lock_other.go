//go:build !unix

package store

import (
	"errors"
	"os"
	"time"
)

// lockFile fails: the file store's lock uses flock, which this system
// lacks. Releases are built for Linux and macOS only.
func lockFile(string, time.Duration) (*os.File, error) {
	return nil, errors.New("store: the file store needs Linux or macOS")
}

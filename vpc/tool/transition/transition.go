package transition

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func LockTransitionNamespaces(ctx context.Context, dir string) (*os.File, func(), error) {
	err := os.Mkdir(dir, 0755)
	if err != nil && !os.IsExist(err) {
		return nil, nil, fmt.Errorf("Unable to mkdir %q: %w", dir, err)
	}

	transitionNamespaceDirFile, err := os.Open(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not open transition namespace directory %q: %w", dir, err)
	}

	for ctx.Err() != nil {
		err := unix.Flock(int(transitionNamespaceDirFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if err != unix.EWOULDBLOCK {
			_ = transitionNamespaceDirFile.Close()
			return nil, nil, fmt.Errorf("Error locking %q: %w", transitionNamespaceDirFile.Name(), ctx.Err())
		}

		select {
		case <-ctx.Done():
			_ = transitionNamespaceDirFile.Close()
			return nil, nil, fmt.Errorf("Timed out: Could not lock %q: %w", transitionNamespaceDirFile.Name(), ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}

	return transitionNamespaceDirFile, func() {
		_ = unix.Flock(int(transitionNamespaceDirFile.Fd()), unix.LOCK_UN)
		_ = transitionNamespaceDirFile.Close()
	}, nil

}

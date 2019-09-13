package spectator

import (
	"os"
	"syscall"
)

func getNumFiles(dir string) (n int, err error) {
	var f *os.File
	var entries []string

	/* #nosec G304 */
	f, err = os.Open(dir)
	if err != nil {
		return 0, err
	}
	defer func() {
		if e := f.Close(); err != nil && e != nil {
			err = e
		}
	}()

	entries, err = f.Readdirnames(-1)
	if err != nil {
		return 0, err
	}
	return len(entries), err
}

func updateFdStats(s *sysStatsCollector, cur int, max uint64) {
	s.curOpen.Set(float64(cur))
	s.maxOpen.Set(float64(max))
}

func fdStats(s *sysStatsCollector) {
	// do not include /proc/self/fd in the count, since it will be opened
	// when we get the number of files under self/fd
	currentFdCount, err := getNumFiles("/proc/self/fd")
	currentFdCount--
	if err != nil {
		s.registry.config.Log.Errorf("Unable to get open files: %v", err)
	}

	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		s.registry.config.Log.Errorf("Unable to get max open files: %v", err)
	}
	maxFdCount := rl.Cur
	updateFdStats(s, currentFdCount, maxFdCount)
}

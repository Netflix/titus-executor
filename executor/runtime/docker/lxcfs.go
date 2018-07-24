package docker

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	lxcfs = "/var/lib/lxcfs"
)

func getlxcfsbindmounts() []string {
	extraBinds := []string{}
	for _, file := range []string{"cpuinfo", "meminfo", "uptime"} {
		path := filepath.Join(lxcfs, "proc", file)
		if err := unix.Access(path, 0444); err != nil {
			destPath := filepath.Join("/proc", file)
			extraBinds = append(extraBinds, fmt.Sprintf("%s:%s", path, destPath))
		}
	}

	return extraBinds
}

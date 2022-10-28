package docker

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	lxcfs = "/var/lib/lxcfs"
)

func getLXCFsBindMounts() []string {
	extraBinds := []string{}
	lxcfsEndpoints := []string{
		"/proc/cpuinfo",
		"/proc/diskstats",
		"/proc/meminfo",
		"/proc/stat",
		"/proc/swaps",
		"/proc/uptime",
		"/proc/slabinfo",
		"/sys/devices/system/cpu/online",
	}
	for _, file := range lxcfsEndpoints {
		path := filepath.Join(lxcfs, file)
		if err := unix.Access(path, 0); err == nil {
			extraBinds = append(extraBinds, fmt.Sprintf("%s:%s", path, file))
		}
	}

	return extraBinds
}

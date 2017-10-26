// +build linux darwin

package main

import (
	"os"
	"syscall"
)

func shutdownSignals() []os.Signal {
	return []os.Signal{syscall.SIGTERM}
}

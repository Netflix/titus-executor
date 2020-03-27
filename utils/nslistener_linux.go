// +build linux

package utils

import (
	"fmt"
	"net"
	"runtime"

	"github.com/pkg/errors"
	"go.uber.org/multierr"

	"github.com/vishvananda/netns"
)

func GetNsListener(netNsPath string, port int) (net.Listener, error) {
	runtime.LockOSThread()
	defer func() {
		runtime.UnlockOSThread()
	}()

	origNs, err := netns.Get()
	if err != nil {
		return nil, errors.Wrap(err, "Unable to save namespace")
	}
	defer func() {
		_ = origNs.Close()
	}()

	dialNs, err := netns.GetFromPath(netNsPath)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to open namespace")
	}
	defer func() {
		_ = dialNs.Close()
	}()

	err = netns.Set(dialNs)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to enter namespace")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))

	errA := netns.Set(origNs)
	if errA != nil {
		errA = errors.Wrap(errA, "Unable to restore namespace")
	}

	return listener, multierr.Combine(err, errA)
}

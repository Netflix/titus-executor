//go:build linux
// +build linux

package netns

import (
	"fmt"
	"net"
	"runtime"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

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

	var errs *multierror.Error

	err = netns.Set(dialNs)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to enter namespace")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	errs = multierror.Append(errs, err)

	err = netns.Set(origNs)
	if err != nil {
		err = errors.Wrap(err, "Unable to restore namespace")
	}
	errs = multierror.Append(errs, err)

	return listener, errs.ErrorOrNil()
}

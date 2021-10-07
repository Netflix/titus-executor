//go:build linux
// +build linux

package netns

import (
	"context"
	"net"
	"runtime"

	"github.com/pkg/errors"
	"go.uber.org/multierr"

	"github.com/vishvananda/netns"
)

func (n *NsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
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

	dialNs, err := netns.GetFromPath(n.netNsPath)
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

	conn, err := n.dialer.DialContext(ctx, network, address)

	errA := netns.Set(origNs)
	if errA != nil {
		errA = errors.Wrap(err, "Unable to restore namespace")
	}

	return conn, multierr.Combine(err, errA)
}

// build +linux

package api

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	titusInits      = "/var/lib/titus-inits"
	curThreadNsPath = "/proc/thread-self/ns/net"
)

// nsDialer is a net.Dialer that does a Setns() into a container's network namespace before doing a connect
type nsDialer struct {
	containerNetNsPath string
	systemDialer       net.Dialer
}

func (d *nsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	log.Debugf("nsDialer: DialContext: %s", d.containerNetNsPath)

	// Make sure that this code executes only in this thread, since `Setns()` changes the thread's namespace
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get the FD for the host namespace, so we can switch back into it after doing the connect
	prevNsFd, err := unix.Open(curThreadNsPath, os.O_RDONLY, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "error opening ns file %s", curThreadNsPath)
	}
	defer unix.Close(prevNsFd)

	nsFd, err := unix.Open(d.containerNetNsPath, os.O_RDONLY, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "error opening ns %s", d.containerNetNsPath)
	}
	defer unix.Close(nsFd)

	if err = unix.Setns(nsFd, unix.CLONE_NEWNET); err != nil {
		return nil, errors.Wrapf(err, "error switching to ns %s", d.containerNetNsPath)
	}

	// Call the system dialer - since we're calling a single URL, the dial will run in this thread, and will
	// therefore do the connect in the container's namespace
	conn, connErr := d.systemDialer.DialContext(ctx, network, address)

	// Switch back to the host namespace now that we're done
	if err = unix.Setns(prevNsFd, unix.CLONE_NEWNET); err != nil {
		return nil, errors.Wrapf(err, "error switching to ns %s", curThreadNsPath)
	}

	return conn, connErr
}

func newDialer(containerID string) (*nsDialer, error) {
	netNsPath := fmt.Sprintf("%s/%s/ns/net", titusInits, containerID)
	_, err := os.Stat(netNsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errUnknownContainer
		}

		return nil, err
	}

	return &nsDialer{
		containerNetNsPath: netNsPath,
		systemDialer: net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: false,
		},
	}, nil
}

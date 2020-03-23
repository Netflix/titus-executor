// build +linux

package api

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"
)

const titusInits = "/var/lib/titus-inits"

// nsDialer is a net.Dialer that does a Setns() into a container's network namespace before doing a connect
type nsDialer struct {
	containerNetNsPath string
	systemDialer       net.Dialer
}

func (d *nsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	log.Debugf("nsDialer: DialContext: %s", d.containerNetNsPath)
	curThreadNsPath := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())

	// Make sure that this code executes only in this thread, since `Setns()` changes the thread's namespace
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get the FD for the host namespace, so we can switch back into it after doing the connect
	prevNsFile, err := os.Open(curThreadNsPath)
	if err != nil {
		return nil, fmt.Errorf("error opening ns file %v: %v", curThreadNsPath, err)
	}
	defer prevNsFile.Close()

	nsFile, err := os.Open(d.containerNetNsPath)
	if err != nil {
		return nil, fmt.Errorf("error opening ns file %v: %v", d.containerNetNsPath, err)
	}
	defer nsFile.Close()

	if err = unix.Setns(int(nsFile.Fd()), unix.CLONE_NEWNET); err != nil {
		return nil, fmt.Errorf("error switching to ns %v: %v", nsFile.Name(), err)
	}

	// Call the system dialer - since we're calling a single URL, the dial will run in this thread, and will
	// therefore do the connect in the container's namespace
	conn, connErr := d.systemDialer.DialContext(ctx, network, address)

	// Switch back to the host namespace now that we're done
	if err = unix.Setns(int(prevNsFile.Fd()), unix.CLONE_NEWNET); err != nil {
		return nil, fmt.Errorf("error switching to ns %v: %v", prevNsFile.Name(), err)
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

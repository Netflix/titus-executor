//go:build linux
// +build linux

package inject

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	tocontainerInterfaceName = "tocontainer"
	toimdsInterfaceName      = "metadataserver"
)

var (
	v6ipnet        *net.IPNet
	v4ipnet        *net.IPNet
	localhostipnet *net.IPNet
	localhost      net.IP
	maxTime        = 14 * time.Second
)

func init() {
	var err error
	_, v6ipnet, err = net.ParseCIDR("fd00:ec2::254/128")
	if err != nil {
		panic(err)
	}

	_, v4ipnet, err = net.ParseCIDR("169.254.169.254/32")
	if err != nil {
		panic(err)
	}

	localhost = net.ParseIP("127.0.0.1")

	_, localhostipnet, err = net.ParseCIDR("127.0.0.1/32")
	if err != nil {
		panic(err)
	}
}

/*
1. It saves the current namespace
2. It opens the container's network namespace at TITUS_PID_1_DIR/ns/net
3. It calls unshare, and creates an entirely new network namespace (intermediate network namespace).
4. It creates a veth pair in the intermediate
5. It adds the IP address 169.254.169.254 to the veth pair
6. It binds to port 80 in the new netns created
7. It moves a side of the veth into the container's network namespace
8. It sets up a route in the container's netns
9. It changes to the PID ns of the container
10. It calls the metadata proxy code
*/
func Inject(ctx context.Context, pid1dir string, subsequentExe []string) error {
	ctx, cancel := context.WithTimeout(ctx, maxTime)
	defer cancel()
	listener, err := setupNamespaces(ctx, pid1dir)
	if err != nil {
		return fmt.Errorf("Could not get listener: %w", err)
	}

	// This is an ugly hack to get a specific FD at a specific number without the O_CLOEXEC flag
	// set.
	err = unix.Dup2(*listener, 169)
	if err != nil {
		return fmt.Errorf("Could not clone FD %d into 169: %w", *listener, err)
	}

	pidns, err := unix.Open(filepath.Join(pid1dir, "ns", "pid"), unix.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("Unable to open pid ns fd: %w", err)
	}

	cmd := exec.Cmd{
		Path:   subsequentExe[0],
		Args:   subsequentExe,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	// Once we've done this setns...who knows how the goruntine will behave.
	runtime.LockOSThread()
	err = unix.Setns(pidns, unix.CLONE_NEWPID)
	if err != nil {
		return fmt.Errorf("Could not enter container pid namespace: %w", err)
	}
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("Unable to execute process: %w", err)
	}
	err = cmd.Wait()
	if exitErr, ok := err.(*exec.ExitError); ok {
		os.Exit(exitErr.ExitCode())
	}

	return fmt.Errorf("Unknown issue: %w", err)
}

// This is a separate function in order to allow for the defer / close statements to execute prior to calling exec
// upon error, the failure state is undefined. Otherwise, on return, it should return to the host namespace.
func setupNamespaces(ctx context.Context, pid1dir string) (*int, error) { // nolint: gocyclo
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hostns, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("Could not get current net ns: %w", err)
	}
	defer hostns.Close()
	hostnsHandle, err := netlink.NewHandleAt(hostns)
	if err != nil {
		return nil, fmt.Errorf("Could not get handle at new host ns: %w", err)
	}
	defer hostnsHandle.Delete()

	path := filepath.Join(pid1dir, "ns", "net")
	containerNSFD, err := unix.Open(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("Could not open %q: %w", path, err)
	}
	defer unix.Close(containerNSFD)
	containerNS := netns.NsHandle(containerNSFD)

	containerNSHandle, err := netlink.NewHandleAt(containerNS)
	if err != nil {
		return nil, fmt.Errorf("Could not get handle at intermediate ns: %w", err)
	}
	defer containerNSHandle.Delete()

	/* This creates the intermediate namespace, and switches us to it */
	intermediateNS, err := netns.New()
	if err != nil {
		return nil, fmt.Errorf("Could not create new intermediate namespace: %w", err)
	}
	defer intermediateNS.Close()
	intermediateNSHandle, err := netlink.NewHandleAt(intermediateNS)
	if err != nil {
		return nil, fmt.Errorf("Could not get handle at intermediate ns: %w", err)
	}
	defer intermediateNSHandle.Delete()

	// This bug here is on Linux 5.10+, where sometimes this returns permission denied.
	// We never go to the bottom of that bug, but simply sleeping and retrying
	// seems to be a good enough work around.
	for try := 1; try <= 5; try++ {
		err = intermediateNSHandle.LinkAdd(&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: tocontainerInterfaceName,
			},
			PeerName: toimdsInterfaceName,
		})
		if err == nil {
			break
		}
		fmt.Printf("DEBUG: error when adding veth in intermediate namespace on try %d (%s). Sleeping and trying again\n", try, err)
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("Could not add veth in intermediate namespace: %w", err)
	}

	tocontainer, err := intermediateNSHandle.LinkByName(tocontainerInterfaceName)
	if err != nil {
		return nil, fmt.Errorf("Could not get tocontainer link: %w", err)
	}

	metadataservice, err := intermediateNSHandle.LinkByName(toimdsInterfaceName)
	if err != nil {
		return nil, fmt.Errorf("Could not get metadataservice link: %w", err)
	}

	err = intermediateNSHandle.LinkSetNsFd(metadataservice, containerNSFD)
	if err != nil {
		return nil, fmt.Errorf("Unable to move metadataservice interface from intermediate network namespace to container network namespace: %w", err)
	}

	err = intermediateNSHandle.LinkSetUp(tocontainer)
	if err != nil {
		return nil, fmt.Errorf("Could not set %q link up: %w", tocontainerInterfaceName, err)
	}

	metadataservice, err = containerNSHandle.LinkByName(toimdsInterfaceName)
	if err != nil {
		return nil, fmt.Errorf("Could not get metadataservice link in container ns: %w", err)
	}

	err = containerNSHandle.LinkSetUp(metadataservice)
	if err != nil {
		return nil, fmt.Errorf("Could not set %q link up: %w", tocontainerInterfaceName, err)
	}

	// We need to do this because even though we set the links in the Linux kernel to up, the process of
	// "the other side" recognizing that the other side is up is handled through an asynchronous process
	// called link_watch.

	// For example, let's say we have veth0 <-> veth1
	// And I set veth0 up. Veth1 still thinks the layer 1 interface is down, until link watch fires
	// at which point it marks layer 1 as up, and subsequently this triggers a bunch of setup.
	err = waitForInterfacesUp(ctx, containerNSHandle, intermediateNSHandle)
	if err != nil {
		return nil, fmt.Errorf("Could not wait for netns to come up: %w", err)
	}

	// Make sure LO is up in the container. This should be a noop:
	lo, err := containerNSHandle.LinkByName("lo")
	if err != nil {
		return nil, fmt.Errorf("Could not get container lo: %w", err)
	}
	err = containerNSHandle.LinkSetUp(lo)
	if err != nil {
		return nil, fmt.Errorf("Could set container lo to up: %w", err)
	}

	// Add the IPs
	err = intermediateNSHandle.AddrAdd(tocontainer, &netlink.Addr{
		IPNet: v4ipnet,
	})
	if err != nil {
		return nil, fmt.Errorf("Could not add %s to interface %q: %w", v4ipnet.String(), tocontainer.Attrs().Name, err)
	}

	err = intermediateNSHandle.AddrAdd(tocontainer, &netlink.Addr{
		IPNet: v6ipnet,
	})
	if err != nil {
		return nil, fmt.Errorf("Could not add %s to interface %q: %w", v6ipnet.String(), tocontainer.Attrs().Name, err)
	}

	metadataserviceLinkLocal, err := getLinkLocalIPv6Addr(ctx, containerNSHandle, metadataservice)
	if err != nil {
		return nil, err
	}

	tocontainerLinkLocal, err := getLinkLocalIPv6Addr(ctx, intermediateNSHandle, tocontainer)
	if err != nil {
		return nil, err
	}

	err = containerNSHandle.RouteAdd(&netlink.Route{
		Via: &netlink.Via{
			AddrFamily: netlink.FAMILY_V6,
			Addr:       tocontainerLinkLocal.IP,
		},
		Dst:       v4ipnet,
		LinkIndex: metadataservice.Attrs().Index,
		Src:       localhost,
	})
	if err != nil {
		return nil, fmt.Errorf("Could not add route to %v: %w", v4ipnet, err)
	}

	err = containerNSHandle.RouteAdd(&netlink.Route{
		Gw:        tocontainerLinkLocal.IP,
		Dst:       v6ipnet,
		LinkIndex: metadataservice.Attrs().Index,
	})
	if err != nil {
		return nil, fmt.Errorf("Could not add route to %v: %w", v6ipnet, err)
	}

	err = intermediateNSHandle.RouteAdd(&netlink.Route{
		Dst:       localhostipnet,
		LinkIndex: tocontainer.Attrs().Index,
	})
	if err != nil {
		return nil, fmt.Errorf("Could not add route to %v: %w", localhostipnet, err)
	}

	// We need to enable localnet routing on in the container namespace on the container -> intermediate device.
	err = netns.Set(containerNS)
	if err != nil {
		return nil, fmt.Errorf("Could not change into container NS: %w", err)
	}
	err = ioutil.WriteFile(filepath.Join("/proc/sys/net/ipv4/conf", toimdsInterfaceName, "route_localnet"), []byte("1"), 0)
	if err != nil {
		return nil, fmt.Errorf("Could not set route_localnet in container NS: %w", err)
	}
	err = ioutil.WriteFile(filepath.Join("/proc/sys/net/ipv4/conf", toimdsInterfaceName, "rp_filter"), []byte("0"), 0)
	if err != nil {
		return nil, fmt.Errorf("Could not set rp_filter in container NS: %w", err)
	}

	// We do this because the otherwise the kernel takes a while for the address to come up. It's a link-local address.
	// We don't need to worry about that.
	err = ioutil.WriteFile(filepath.Join("/proc/sys/net/ipv6/conf", toimdsInterfaceName, "accept_dad"), []byte("0"), 0)
	if err != nil {
		return nil, fmt.Errorf("Could not set accept_dad in container NS: %w", err)
	}

	// All is primed. Let's setup the listener
	err = netns.Set(intermediateNS)
	if err != nil {
		return nil, fmt.Errorf("Could not change into intermediate NS: %w", err)
	}
	err = ioutil.WriteFile(filepath.Join("/proc/sys/net/ipv4/conf", tocontainerInterfaceName, "route_localnet"), []byte("1"), 0)
	if err != nil {
		return nil, fmt.Errorf("Could not set route_localnet in container NS: %w", err)
	}

	err = ioutil.WriteFile(filepath.Join("/proc/sys/net/ipv6/conf", tocontainerInterfaceName, "accept_dad"), []byte("0"), 0)
	if err != nil {
		return nil, fmt.Errorf("Could not set accept_dad in container NS: %w", err)
	}

	socket, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("Could not create listener socket: %w", err)
	}
	err = unix.Bind(socket, &unix.SockaddrInet6{
		Port: 80,
		// Wildcard?
		Addr: [16]byte{},
	})
	if err != nil {
		return nil, fmt.Errorf("Could not bind listener socket: %w", err)
	}

	err = containerNSHandle.NeighSet(&netlink.Neigh{
		LinkIndex:    metadataservice.Attrs().Index,
		Family:       netlink.FAMILY_V6,
		State:        netlink.NUD_PERMANENT,
		Type:         unix.RTN_UNICAST,
		IP:           tocontainerLinkLocal.IP,
		HardwareAddr: tocontainer.Attrs().HardwareAddr,
	})
	if err != nil {
		return nil, fmt.Errorf("Cannot insert neighbor entry %w from container NS to imds NS", err)
	}

	err = intermediateNSHandle.NeighSet(&netlink.Neigh{
		LinkIndex:    tocontainer.Attrs().Index,
		Family:       netlink.FAMILY_V6,
		State:        netlink.NUD_PERMANENT,
		Type:         unix.RTN_UNICAST,
		IP:           metadataserviceLinkLocal.IP,
		HardwareAddr: metadataservice.Attrs().HardwareAddr,
	})
	if err != nil {
		return nil, fmt.Errorf("Cannot insert neighbor entry %w from imds NS to container NS", err)
	}

	err = unix.Listen(socket, 128)
	if err != nil {
		return nil, fmt.Errorf("Could not set listen queue on listener socket: %w", err)
	}

	err = netns.Set(hostns)
	if err != nil {
		return nil, fmt.Errorf("Could not change back into host NS: %w", err)
	}

	return &socket, nil
}

// getLinkLocalIPv6Addr gets the SCOPE_LINK / Link-local address for a given link. It does this by polling
// the addresses on the link.
func getLinkLocalIPv6Addr(ctx context.Context, handle *netlink.Handle, link netlink.Link) (*netlink.Addr, error) {
	t := time.NewTimer(1)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("Context complete before able to get LL addrs: %w", ctx.Err())
		case <-t.C:
			addrs, err := handle.AddrList(link, netlink.FAMILY_V6)
			if err != nil {
				return nil, fmt.Errorf("Could not list V6 addrs on %q: %w", link.Attrs().Name, err)
			}
			for idx := range addrs {
				addr := addrs[idx]
				logger.G(ctx).Debugf("Checking addr %v, with flags %d", addr.IP, addr.Flags)
				if addr.Scope == int(netlink.SCOPE_LINK) {
					return &addr, nil
				}
			}
		}
		t.Reset(10 * time.Millisecond)
	}
}

func waitForInterfacesUp(ctx context.Context, containerNSHandle, intermediateNSHandle *netlink.Handle) error {
	t := time.NewTimer(1)
	defer t.Stop()
	var err error
	var toIMDSLink, toContainerLink netlink.Link
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("Context complete before expected: %w, last states; toIMDSLink: %v, toContainerLink:%v", ctx.Err(), toIMDSLink, toContainerLink)
		case <-t.C:
			toIMDSLink, err = containerNSHandle.LinkByName(toimdsInterfaceName)
			if err != nil {
				return fmt.Errorf("Could not get %s: %w", toimdsInterfaceName, err)
			}

			toContainerLink, err = intermediateNSHandle.LinkByName(tocontainerInterfaceName)
			if err != nil {
				return fmt.Errorf("Could not get %s: %w", tocontainerInterfaceName, err)
			}

			if toIMDSLink.Attrs().OperState == netlink.OperUp &&
				toContainerLink.Attrs().OperState == netlink.OperUp &&
				toIMDSLink.Attrs().Flags&net.FlagUp == net.FlagUp &&
				toContainerLink.Attrs().Flags&net.FlagUp == net.FlagUp {
				return nil
			}
			// I think that the upper bound for processing in link_watch should be around 1 second.
			t.Reset(10 * time.Millisecond)
		}
	}
}

// +build linux

package setup_container

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	mtu              = 9000
	hz               = 100.0
	networkSetupWait = 30 * time.Second
)

var (
	errLinkNotFound        = errors.New("Link not found")
	errAddressSetupTimeout = errors.New("IPv6 address setup timed out")
)

func doSetupContainer(ctx context.Context, netnsfd int, bandwidth, ceil uint64, jumbo bool, allocation types.Allocation) (netlink.Link, error) {
	parentLink, err := getLinkByMac(allocation.MAC)
	if err != nil {
		return nil, err
	}

	nsHandle, err := netlink.NewHandleAt(netns.NsHandle(netnsfd))
	if err != nil {
		return nil, err
	}
	defer nsHandle.Delete()

	mtu := parentLink.Attrs().MTU
	if !jumbo {
		mtu = 1500
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	containerInterfaceName := fmt.Sprintf("tmp-%d", r.Intn(10000))
	ipvlan := netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        containerInterfaceName,
			ParentIndex: parentLink.Attrs().Index,
			Namespace:   netlink.NsFd(netnsfd),
			MTU:         mtu,
			TxQLen:      -1,
		},
		Mode: netlink.IPVLAN_MODE_L2,
	}

	err = netlink.LinkAdd(&ipvlan)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not add link")
		return nil, err
	}
	// If things fail here, it's fairly bad, because we've added the link to the namespace, but we don't know
	// what it's index is, so there's no point returning it.
	logger.G(ctx).Debugf("Added link: %+v ", ipvlan)
	newLink, err := nsHandle.LinkByName(containerInterfaceName)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not find after adding link")
		return nil, err
	}

	return newLink, configureLink(ctx, nsHandle, newLink, bandwidth, ceil, mtu, allocation)
}

func addIPv4AddressAndRoute(ctx context.Context, nsHandle *netlink.Handle, link netlink.Link, address *vpcapi.UsableAddress) error {
	if address.Address.Family != titus.Family_FAMILY_V4 {
		panic("Trying to configure networking with invalid family")
	}
	mask := net.CIDRMask(int(address.Address.PrefixLength), 32)
	ip := net.ParseIP(address.Address.Address)

	// The netlink package appears to automatically calculate broadcast
	new4Addr := netlink.Addr{
		IPNet: &net.IPNet{IP: ip, Mask: mask},
	}
	err := nsHandle.AddrAdd(link, &new4Addr)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to add IPv4 addr to link")
		return err
	}

	gateway := net.ParseIP(address.Gateway.Address)
	newRoute := netlink.Route{
		Gw:        gateway,
		Src:       ip,
		LinkIndex: link.Attrs().Index,
	}
	err = nsHandle.RouteAdd(&newRoute)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to add route to link")
		return err
	}

	return nil
}

func configureLink(ctx context.Context, nsHandle *netlink.Handle, link netlink.Link, bandwidth, ceil uint64, mtu int, allocation types.Allocation) error {
	// Rename link
	err := nsHandle.LinkSetName(link, "eth0")
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to set link name")
		return err
	}
	err = nsHandle.LinkSetUp(link)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to set link up")
		return err
	}

	err = nsHandle.LinkSetMTU(link, mtu)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to set link mtu")
		return err
	}

	if allocation.IPV6Address != nil {
		// Amazon only gives out /128s
		new6Addr := netlink.Addr{
			// TODO (Sargun): Check IP Mask setting.
			IPNet: &net.IPNet{IP: net.ParseIP(allocation.IPV6Address.Address.Address), Mask: net.CIDRMask(128, 128)},
		}
		err = nsHandle.AddrAdd(link, &new6Addr)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Unable to add IPv6 addr to link")
			return err
		}
	}

	err = addIPv4AddressAndRoute(ctx, nsHandle, link, allocation.IPV4Address)
	if err != nil {
		return err
	}

	// TODO: Wire up IFB / BPF / Bandwidth limits for IPv6
	err = setupIFBClasses(ctx, bandwidth, ceil, net.ParseIP(allocation.IPV4Address.Address.Address))
	if err != nil {
		return err
	}
	if allocation.IPV6Address != nil {
		return waitForAddressUp(ctx, nsHandle, link)
	}
	return nil
}

// This checks if we have a globally-scoped, non-tentative IPv6 address
func isIPv6Ready(nsHandle *netlink.Handle, link netlink.Link) (bool, error) {
	addrs, err := nsHandle.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		if addr.Scope == int(netlink.SCOPE_UNIVERSE) && addr.Flags&unix.IFA_F_TENTATIVE == 0 {
			return true, nil
		}
	}
	return false, nil
}

func waitForAddressUp(ctx context.Context, nsHandle *netlink.Handle, link netlink.Link) error {
	ctx, cancel := context.WithTimeout(ctx, networkSetupWait)
	defer cancel()
	pollTimer := time.NewTicker(100 * time.Millisecond)
	defer pollTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return errAddressSetupTimeout
		case <-pollTimer.C:
			if found, err := isIPv6Ready(nsHandle, link); err != nil {
				return err
			} else if found {
				return nil
			}
		}
	}
}

func setupIFBClasses(ctx context.Context, bandwidth, ceil uint64, ip net.IP) error {
	// The class is based on the last two parts of the IPv4 address
	// The reasoning is that 0 and 1 of the subnet are reserved by Amazon, so we will never get those IPs
	// and VPCs can never have subnets that are larger than /16. Each instance is scoped to a single subnet,
	// so it should never have a collision

	// At least this is true as of the time of writing
	ifbEgress, err := netlink.LinkByName(vpc.EgressIFB)
	if err != nil {
		return err
	}

	ifbIngress, err := netlink.LinkByName(vpc.IngressIFB)
	if err != nil {
		return err
	}

	err = setupIFBClass(ctx, bandwidth, ceil, ip, ifbEgress)
	if err != nil {
		return err
	}
	err = setupIFBSubqdisc(ctx, ip, ifbEgress)
	if err != nil {
		return err
	}

	err = setupIFBClass(ctx, bandwidth, ceil, ip, ifbIngress)
	if err != nil {
		return err
	}
	return setupIFBSubqdisc(ctx, ip, ifbIngress)
}

func setupIFBSubqdisc(ctx context.Context, ip net.IP, link netlink.Link) error {
	handle := ipaddressToHandle(ip)

	// The qdisc wasn't found, add it
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(handle, 0),
		Parent:    netlink.MakeHandle(1, handle),
	}
	qdisc := netlink.NewFqCodel(attrs)
	qdisc.Quantum = 9001

	err := netlink.QdiscAdd(qdisc)
	if err != nil && err != unix.EEXIST {
		return err
	}

	return nil
}

func setupIFBClass(ctx context.Context, bandwidth, ceil uint64, ip net.IP, link netlink.Link) error {
	handle := ipaddressToHandle(ip)

	classattrs := netlink.ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.MakeHandle(1, 1),
		// We assume that
		Handle: netlink.MakeHandle(1, handle),
	}

	htbclassattrs := netlink.HtbClassAttrs{
		Rate:    bandwidth,
		Ceil:    ceil,
		Buffer:  uint32(float64(bandwidth)/(hz*8) + float64(mtu)),
		Cbuffer: uint32(float64(ceil)/(hz*8) + float64(mtu)),
	}
	class := netlink.NewHtbClass(classattrs, htbclassattrs)
	logger.G(ctx).Debug("Setting up HTB class: ", class)

	err := netlink.ClassAdd(class)
	if err != nil {
		logger.G(ctx).WithError(err).Warning("Could not add class")
		return netlink.ClassReplace(class)
	}
	return nil
}

func getLinkByMac(mac string) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		if link.Attrs().HardwareAddr.String() == mac {
			return link, nil
		}
	}

	return nil, errLinkNotFound
}

func ipaddressToHandle(ip net.IP) uint16 {
	return binary.BigEndian.Uint16([]byte(ip.To4()[2:4]))
}

func teardownNetwork(ctx context.Context, allocation types.Allocation, link netlink.Link, netnsfd int) {
	deleteLink(ctx, link, netnsfd)
	ip := net.ParseIP(allocation.IPV4Address.Address.Address)

	// Removing the classes automatically removes the qdiscs
	ifbEgress, err := netlink.LinkByName(vpc.EgressIFB)
	if err == nil {
		removeClass(ctx, ip, ifbEgress)
	} else {
		logger.G(ctx).WithError(err).Warning("Unable to find ifb egress, during deallocation")
	}

	ifbIngress, err := netlink.LinkByName(vpc.IngressIFB)
	if err == nil {
		removeClass(ctx, ip, ifbIngress)
	} else {
		logger.G(ctx).WithError(err).Warning("Unable to find ifb ingress, during deallocation")
	}
}

func deleteLink(ctx context.Context, link netlink.Link, netnsfd int) {
	if link == nil {
		logger.G(ctx).Debug("Link not setup, not deleting link")
		return
	}
	nsHandle, err := netlink.NewHandleAt(netns.NsHandle(netnsfd))
	if err != nil {
		logger.G(ctx).Warning("Unable to get handle")
		return
	}
	defer nsHandle.Delete()
	err = nsHandle.LinkDel(link)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to delete link")
	}
}

func removeClass(ctx context.Context, ip net.IP, link netlink.Link) {
	handle := ipaddressToHandle(ip)
	classes, err := netlink.ClassList(link, netlink.MakeHandle(1, 1))
	if err != nil {
		logger.G(ctx).Errorf("Unable to list classes on link %v because %v", link, err)
		return
	}
	for _, class := range classes {
		htbClass := class.(*netlink.HtbClass)
		logger.G(ctx).Debug("Class: ", class)
		logger.G(ctx).Debug("Class: ", class.Attrs())

		if htbClass.Attrs().Handle == netlink.MakeHandle(1, handle) {
			err = netlink.ClassDel(class)
			if err != nil {
				logger.G(ctx).WithError(err).Warning("Unable to remove class")
			}
			return
		}
	}

	logger.G(ctx).Warning("Unable to find class for container")
}

// +build linux

package allocate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"time"

	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/context"
	"github.com/Netflix/titus-executor/vpc/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/apparentlymart/go-cidr/cidr"
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

func doSetupContainer(parentCtx *context.VPCContext, netnsfd int, bandwidth uint64, burst, jumbo bool, allocation types.Allocation) (netlink.Link, error) {

	networkInterface, err := getInterfaceByIdx(parentCtx, allocation.DeviceIndex)
	if err != nil {
		parentCtx.Logger.Error("Cannot get interface by index: ", err)
		return nil, err
	}

	ip4 := net.ParseIP(allocation.IPV4Address)
	ip6 := net.ParseIP(allocation.IPV6Address)
	parentLink, err := getLink(networkInterface)
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
		parentCtx.Logger.Error("Could not add link: ", err)
		return nil, err
	}
	// If things fail here, it's fairly bad, because we've added the link to the namespace, but we don't know
	// what it's index is, so there's no point returning it.
	parentCtx.Logger.Debugf("Added link: %+v ", ipvlan)
	newLink, err := nsHandle.LinkByName(containerInterfaceName)
	if err != nil {
		parentCtx.Logger.Error("Could not find after adding link: ", err)
		return nil, err
	}

	return newLink, configureLink(parentCtx, nsHandle, newLink, bandwidth, mtu, burst, networkInterface, ip4, ip6)
}

func addIPv4AddressAndRoute(parentCtx *context.VPCContext, networkInterface ec2wrapper.NetworkInterface, nsHandle *netlink.Handle, link netlink.Link, ip net.IP) error {
	subnet, err := parentCtx.Cache.DescribeSubnet(parentCtx, networkInterface.GetSubnetID())
	if err != nil {
		return err
	}

	// We assume that it always gives us the subnet
	_, ipnet, err := net.ParseCIDR(*subnet.CidrBlock)
	if err != nil {
		return err
	}

	// The netlink package appears to automatically calculate broadcast
	new4Addr := netlink.Addr{
		IPNet: &net.IPNet{IP: ip, Mask: ipnet.Mask},
	}
	err = nsHandle.AddrAdd(link, &new4Addr)
	if err != nil {
		parentCtx.Logger.Error("Unable to add IPv4 addr to link: ", err)
		return err
	}

	gateway := cidr.Inc(ipnet.IP)
	newRoute := netlink.Route{
		Gw:        gateway,
		Src:       ip,
		LinkIndex: link.Attrs().Index,
	}
	err = nsHandle.RouteAdd(&newRoute)
	if err != nil {
		parentCtx.Logger.Error("Unable to add route to link: ", err)
		return err
	}

	return nil
}

func configureLink(parentCtx *context.VPCContext, nsHandle *netlink.Handle, link netlink.Link, bandwidth uint64, mtu int, burst bool, networkInterface ec2wrapper.NetworkInterface, ip4, ip6 net.IP) error {
	// Rename link
	err := nsHandle.LinkSetName(link, "eth0")
	if err != nil {
		parentCtx.Logger.Error("Unable to set link name: ", err)
		return err
	}
	err = nsHandle.LinkSetUp(link)
	if err != nil {
		parentCtx.Logger.Error("Unable to set link up: ", err)
		return err
	}

	err = nsHandle.LinkSetMTU(link, mtu)
	if err != nil {
		parentCtx.Logger.Error("Unable to set link mtu: ", err)
		return err
	}

	if ip6 != nil {
		// Amazon only gives out /128s
		new6Addr := netlink.Addr{
			IPNet: &net.IPNet{IP: ip6, Mask: net.CIDRMask(128, 128)},
		}
		err = nsHandle.AddrAdd(link, &new6Addr)
		if err != nil {
			parentCtx.Logger.Error("Unable to add IPv6 addr to link: ", err)
			return err
		}
	}

	err = addIPv4AddressAndRoute(parentCtx, networkInterface, nsHandle, link, ip4)
	if err != nil {
		return err
	}

	// TODO: Wire up IFB / BPF / Bandwidth limits for IPv6
	err = setupIFBClasses(parentCtx, bandwidth, burst, ip4)
	if err != nil {
		return err
	}
	if ip6 != nil {
		return waitForAddressUp(parentCtx, nsHandle, link)
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

func waitForAddressUp(parentCtx *context.VPCContext, nsHandle *netlink.Handle, link netlink.Link) error {
	ctx, cancel := parentCtx.WithTimeout(networkSetupWait)
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

func setupIFBClasses(parentCtx *context.VPCContext, bandwidth uint64, burst bool, ip net.IP) error {
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

	err = setupIFBClass(parentCtx, bandwidth, burst, ip, ifbEgress)
	if err != nil {
		return err
	}
	err = setupIFBSubqdisc(parentCtx, ip, ifbEgress)
	if err != nil {
		return err
	}

	err = setupIFBClass(parentCtx, bandwidth, burst, ip, ifbIngress)
	if err != nil {
		return err
	}
	return setupIFBSubqdisc(parentCtx, ip, ifbIngress)
}

func setupIFBSubqdisc(parentCtx *context.VPCContext, ip net.IP, link netlink.Link) error {
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

func setupIFBClass(parentCtx *context.VPCContext, bandwidth uint64, burst bool, ip net.IP, link netlink.Link) error {
	handle := ipaddressToHandle(ip)

	classattrs := netlink.ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.MakeHandle(1, 1),
		// We assume that
		Handle: netlink.MakeHandle(1, handle),
	}

	ceil := bandwidth
	if burst {
		ceil = vpc.GetMaxNetworkbps(parentCtx.InstanceType)
	}
	htbclassattrs := netlink.HtbClassAttrs{
		Rate:    bandwidth,
		Ceil:    ceil,
		Buffer:  uint32(float64(bandwidth)/(hz*8) + float64(mtu)),
		Cbuffer: uint32(float64(ceil)/(hz*8) + float64(mtu)),
	}
	class := netlink.NewHtbClass(classattrs, htbclassattrs)
	parentCtx.Logger.Debug("Setting up HTB class: ", class)

	err := netlink.ClassAdd(class)
	if err != nil {
		parentCtx.Logger.Warning("Could not add class: ", err)
		return netlink.ClassReplace(class)
	}
	return nil
}

func getLink(networkInterface ec2wrapper.NetworkInterface) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	mac, err := net.ParseMAC(networkInterface.GetMAC())
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		if reflect.DeepEqual(link.Attrs().HardwareAddr, mac) {
			return link, nil
		}
	}

	return nil, errLinkNotFound
}

func ipaddressToHandle(ip net.IP) uint16 {
	return binary.BigEndian.Uint16([]byte(ip.To4()[2:4]))
}

func teardownNetwork(ctx *context.VPCContext, allocation types.Allocation, link netlink.Link, netnsfd int) {
	deleteLink(ctx, link, netnsfd)
	ip := net.ParseIP(allocation.IPV4Address)

	// Removing the classes automatically removes the qdiscs
	ifbEgress, err := netlink.LinkByName(vpc.EgressIFB)
	if err == nil {
		removeClass(ctx, ip, ifbEgress)
	} else {
		ctx.Logger.Warning("Unable to find ifb egress, during deallocation: ", err)
	}

	ifbIngress, err := netlink.LinkByName(vpc.IngressIFB)
	if err == nil {
		removeClass(ctx, ip, ifbIngress)
	} else {
		ctx.Logger.Warning("Unable to find ifb ingress, during deallocation: ", err)
	}
}

func deleteLink(ctx *context.VPCContext, link netlink.Link, netnsfd int) {
	if link == nil {
		ctx.Logger.Debug("Link not setup, not deleting link")
		return
	}
	nsHandle, err := netlink.NewHandleAt(netns.NsHandle(netnsfd))
	if err != nil {
		ctx.Logger.Warning("Unable to get handle")
	}
	defer nsHandle.Delete()
	err = nsHandle.LinkDel(link)
	if err != nil {
		ctx.Logger.Error("Unable to delete link: ", err)
	}
}

func removeClass(ctx *context.VPCContext, ip net.IP, link netlink.Link) {
	handle := ipaddressToHandle(ip)
	classes, err := netlink.ClassList(link, netlink.MakeHandle(1, 1))
	if err != nil {
		ctx.Logger.Errorf("Unable to list classes on link %v because %v", link, err)
		return
	}
	for _, class := range classes {
		htbClass := class.(*netlink.HtbClass)
		ctx.Logger.Debug("Class: ", class)
		ctx.Logger.Debug("Class: ", class.Attrs())

		if htbClass.Attrs().Handle == netlink.MakeHandle(1, handle) {
			err = netlink.ClassDel(class)
			if err != nil {
				ctx.Logger.Warning("Unable to remove class: ", err)
			}
			return
		}
	}

	ctx.Logger.Warning("Unable to find class for container")
}

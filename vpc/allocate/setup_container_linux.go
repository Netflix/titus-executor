// +build linux

package allocate

import (
	"encoding/binary"
	"errors"
	"net"
	"reflect"

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
	containerInterfaceName = "eth0-tmp"
	mtu                    = 9000
)

var (
	errLinkNotFound = errors.New("Link not found")
)

func doSetupContainer(parentCtx *context.VPCContext, netnsfd, bandwidth int, burst bool, allocation types.Allocation) (netlink.Link, error) {
	networkInterface, err := getInterfaceByIdx(parentCtx, allocation.DeviceIndex)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(allocation.IPV4Address)

	parentLink, err := getLink(networkInterface)
	if err != nil {
		return nil, err
	}

	nsHandle, err := netlink.NewHandleAt(netns.NsHandle(netnsfd))
	if err != nil {
		return nil, err
	}
	defer nsHandle.Delete()

	ipvlan := netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        containerInterfaceName,
			ParentIndex: parentLink.Attrs().Index,
			Namespace:   netlink.NsFd(netnsfd),
			MTU:         parentLink.Attrs().MTU,
			TxQLen:      -1,
		},
		Mode: netlink.IPVLAN_MODE_L2,
	}

	err = netlink.LinkAdd(&ipvlan)
	if err != nil {
		return nil, err
	}
	// If things fail here, it's fairly bad, because we've added the link to the namespace, but we don't know
	// what it's index is, so there's no point returning it.
	parentCtx.Logger.Debugf("Added link: %+v ", ipvlan)
	newLink, err := nsHandle.LinkByName(containerInterfaceName)
	if err != nil {
		return nil, err
	}

	return newLink, configureLink(parentCtx, nsHandle, newLink, bandwidth, burst, networkInterface, ip)
}

func configureLink(parentCtx *context.VPCContext, nsHandle *netlink.Handle, link netlink.Link, bandwidth int, burst bool, networkInterface *ec2wrapper.EC2NetworkInterface, ip net.IP) error {
	// Rename link
	err := nsHandle.LinkSetName(link, "eth0")
	if err != nil {
		return err
	}
	err = nsHandle.LinkSetUp(link)
	if err != nil {
		return err
	}

	subnet, err := parentCtx.SubnetCache.DescribeSubnet(parentCtx, networkInterface.SubnetID)
	if err != nil {
		return err
	}

	// We assume that it always gives us the subnet
	_, ipnet, err := net.ParseCIDR(*subnet.CidrBlock)
	if err != nil {
		return err
	}

	// The netlink package appears to automatically calculate broadcast
	newAddr := netlink.Addr{
		IPNet: &net.IPNet{IP: ip, Mask: ipnet.Mask},
	}
	err = nsHandle.AddrAdd(link, &newAddr)
	if err != nil {
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
		return err
	}

	return setupIFBClasses(parentCtx, bandwidth, burst, ip)
}

func setupIFBClasses(parentCtx *context.VPCContext, bandwidth int, burst bool, ip net.IP) error {
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

	err := netlink.QdiscAdd(qdisc)
	if err != nil && err != unix.EEXIST {
		return err
	}

	return nil
}

func setupIFBClass(parentCtx *context.VPCContext, bandwidth int, burst bool, ip net.IP, link netlink.Link) error {
	handle := ipaddressToHandle(ip)

	classattrs := netlink.ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.MakeHandle(1, 1),
		// We assume that
		Handle: netlink.MakeHandle(1, handle),
	}

	ceil := uint64(bandwidth)
	if burst {
		ceil = vpc.GetMaxNetworkbps(parentCtx.InstanceType)
	}
	htbclassattrs := netlink.HtbClassAttrs{
		Rate:    uint64(bandwidth),
		Ceil:    ceil,
		Buffer:  uint32(float64(bandwidth/8)/netlink.Hz() + float64(mtu)),
		Cbuffer: uint32(float64(ceil/8)/netlink.Hz() + float64(mtu)),
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

func getLink(networkInterface *ec2wrapper.EC2NetworkInterface) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	mac, err := net.ParseMAC(networkInterface.MAC)
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

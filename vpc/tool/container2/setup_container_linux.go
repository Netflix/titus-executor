//go:build linux
// +build linux

package container2

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"
	"runtime"
	"time"
	"unsafe"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/setup2"
	"github.com/apparentlymart/go-cidr/cidr"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	networkSetupWait = 30 * time.Second
	// Ethernet II framing overhead
	framingOverhead = 20
)

var (
	errNoRoutesReceived = errors.New("No routes receives from Titus VPC Service")
)

func getBranchLink(ctx context.Context, assignment *vpcapi.AssignIPResponseV3) (netlink.Link, error) {
	trunkLink, err := setup2.GetLinkByMac(assignment.TrunkNetworkInterface.MacAddress)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot find trunk link")
	}

	vlanLinkName := fmt.Sprintf("vlan%d", assignment.VlanId)
	vlanLink, err := netlink.LinkByName(vlanLinkName)
	if err != nil {
		_, ok := err.(netlink.LinkNotFoundError)
		if ok {
			// Just need to add this link
			err = netlink.LinkAdd(&netlink.Vlan{
				LinkAttrs: netlink.LinkAttrs{
					ParentIndex: trunkLink.Attrs().Index,
					Name:        vlanLinkName,
				},
				VlanId:       int(assignment.VlanId),
				VlanProtocol: netlink.VLAN_PROTOCOL_8021Q,
			})
			if err != nil && err != unix.EEXIST {
				return nil, errors.Wrap(err, "Cannot add vlan link")
			}
			vlanLink, err = netlink.LinkByName(vlanLinkName)
		}
		if err != nil {
			return nil, errors.Wrap(err, "Cannot get vlan link by name")
		}
	}

	if vlanLink.Attrs().HardwareAddr.String() != assignment.BranchNetworkInterface.MacAddress {
		mac, err := net.ParseMAC(assignment.BranchNetworkInterface.MacAddress)
		if err != nil {
			return nil, errors.Wrapf(err, "Cannot parse mac %q", assignment.BranchNetworkInterface.MacAddress)
		}
		err = netlink.LinkSetHardwareAddr(vlanLink, mac)
		if err != nil {
			return nil, errors.Wrap(err, "Cannot update branch ENI mac")
		}
	}

	return vlanLink, nil
}

func DoSetupContainer(ctx context.Context, pid1dirfd int, assignment *vpcapi.AssignIPResponseV3) error {
	logger.G(ctx).WithField("assignment", assignment.String()).Info("Configuring networking with assignment")
	branchLink, err := getBranchLink(ctx, assignment)
	if err != nil {
		return err
	}

	netnsfd, err := unix.Openat(pid1dirfd, "ns/net", unix.O_CLOEXEC, unix.O_RDONLY)
	if err != nil {
		return fmt.Errorf("Cannot open / get netns fd: %w", err)
	}
	defer unix.Close(netnsfd)

	nsHandle, err := netlink.NewHandleAt(netns.NsHandle(netnsfd))
	if err != nil {
		return err
	}
	defer nsHandle.Delete()

	r := rand.New(rand.NewSource(time.Now().UnixNano())) // nolint: gosec
	containerInterfaceName := fmt.Sprintf("tmp-%d", r.Intn(10000))
	ipvlan := netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        containerInterfaceName,
			ParentIndex: branchLink.Attrs().Index,
			Namespace:   netlink.NsFd(netnsfd),
			TxQLen:      -1,
		},
		Mode: netlink.IPVLAN_MODE_L2,
	}

	err = netlink.LinkAdd(&ipvlan)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not add link")
		return errors.Wrapf(err, "Cannot create link with name %s", containerInterfaceName)
	}
	// If things fail here, it's fairly bad, because we've added the link to the namespace, but we don't know
	// what it's index is, so there's no point returning it.
	logger.G(ctx).Debugf("Added link: %+v ", ipvlan)
	newLink, err := nsHandle.LinkByName(containerInterfaceName)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not find after adding link")
		return errors.Wrapf(err, "Cannot find link with name %s", containerInterfaceName)
	}

	return configureLink(ctx, nsHandle, newLink, assignment)
}

func addIPv4AddressAndRoutes(ctx context.Context, nsHandle *netlink.Handle, link netlink.Link, address *vpcapi.UsableAddress, routes []*vpcapi.AssignIPResponseV3_Route) error {
	mask := net.CIDRMask(int(address.PrefixLength), 32)
	ip := net.ParseIP(address.Address.Address)

	ctx = logger.WithField(logger.WithField(ctx, "mask", mask), "ip", address.Address.Address)
	logger.G(ctx).Debug("Adding IPV4 address and route")
	// The netlink package appears to automatically calculate broadcast
	ipnet := &net.IPNet{IP: ip, Mask: mask}
	new4Addr := netlink.Addr{
		IPNet: ipnet,
		// This forces all traffic through the gateway, which is the AWS virtual gateway / phantom router
		// this is beneficial for two reasons:
		// 1. No ARP needed because you only ever need to learn the ARP / neighbor entry of the default gateway
		// 2. It means that certain security things are enforced
		Flags: unix.IFA_F_NOPREFIXROUTE,
	}
	err := nsHandle.AddrAdd(link, &new4Addr)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to add IPv4 addr to link")
		return errors.Wrap(err, "Unable to add IPv4 addr to link")
	}

	gateway := cidr.Inc(ip.Mask(mask))
	if len(routes) == 0 {
		return errNoRoutesReceived
	}

	// Add a /32 route on the link to *only* the virtual gateway / phantom router
	logger.G(ctx).WithField("gateway", gateway).Debug("Adding gateway route")
	gatewayRoute := netlink.Route{
		Dst:       &net.IPNet{IP: gateway, Mask: net.CIDRMask(32, 32)},
		Src:       ip,
		LinkIndex: link.Attrs().Index,
		Scope:     unix.RT_SCOPE_LINK,
	}
	err = nsHandle.RouteAdd(&gatewayRoute)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to add route to link")
		return errors.Wrap(err, "Unable to add gateway route to link")
	}

	for _, route := range routes {
		if route.Family != vpcapi.AssignIPResponseV3_Route_IPv4 {
			continue
		}
		logger.G(ctx).WithField("route", route).Debug("Adding route")
		_, routeNet, err := net.ParseCIDR(route.Destination)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Could not parse route")
			return fmt.Errorf("Could not parse route CIDR (%s): %w", route.Destination, err)
		}
		newRoute := netlink.Route{
			Gw:        gateway.To4(),
			Src:       ip,
			LinkIndex: link.Attrs().Index,
			Dst:       routeNet,
			MTU:       int(route.Mtu),
		}
		err = nsHandle.RouteAdd(&newRoute)
		if err != nil {
			logger.G(ctx).WithField("route", route).WithError(err).Error("Unable to add route to link")
			return fmt.Errorf("Unable to add route %v to link due to: %w", route, err)
		}
	}

	return nil
}

func configureLink(ctx context.Context, nsHandle *netlink.Handle, link netlink.Link, assignment *vpcapi.AssignIPResponseV3) error {
	// Rename link
	err := nsHandle.LinkSetName(link, "eth0")
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to set link name")
		return errors.Wrapf(err, "Unable to rename link from %s to eth0", link.Attrs().Name)
	}
	err = nsHandle.LinkSetUp(link)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to set link up")
		return errors.Wrap(err, "Unable to set link up")
	}

	if assignment.Ipv4Address != nil {
		err = addIPv4AddressAndRoutes(ctx, nsHandle, link, assignment.Ipv4Address, assignment.Routes)
		if err != nil {
			return fmt.Errorf("Unable to setup IPv4 address: %w", err)
		}
	}

	if assignment.Ipv6Address != nil {
		err = addIPv6AddressAndRoutes(ctx, assignment, nsHandle, link)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Unable to add IPv6 address")
			return fmt.Errorf("Unable to setup IPv6 address: %w", err)
		}
	}

	err = updateBPFMaps(ctx, assignment)
	if err != nil {
		return err
	}

	err = setupHTBClasses(ctx, assignment.Bandwidth, link.Attrs().MTU, uint16(assignment.ClassId), assignment.TrunkNetworkInterface.MacAddress)
	if err != nil {
		return err
	}

	return nil
}

func addIPv6AddressAndRoutes(ctx context.Context, assignment *vpcapi.AssignIPResponseV3, nsHandle *netlink.Handle, link netlink.Link) error {
	ctx, cancel := context.WithTimeout(ctx, networkSetupWait)
	defer cancel()

	// The executor relies on docker.go to set accept_ra_pinfo to 0. When eth0 is created, it doesn't get a prefix route
	//
	// We mimic the behaaviour on IPv4 by forcing all traffic through the default gateway.
	// The reason is that we want to avoid learning ARP / doing neighbor discovery, and rely
	// on the gateway to do this heavy lifting.

	// Amazon only gives out /128s
	new6IP := net.IPNet{IP: net.ParseIP(assignment.Ipv6Address.Address.Address), Mask: net.CIDRMask(128, 128)}
	new6Addr := netlink.Addr{
		// TODO (Sargun): Check IP Mask setting.
		IPNet: &new6IP,
		Flags: unix.IFA_F_PERMANENT | unix.IFA_F_NODAD | unix.IFA_F_NOPREFIXROUTE,
		Scope: unix.RT_SCOPE_UNIVERSE,
	}
	err := nsHandle.AddrAdd(link, &new6Addr)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to add IPv6 addr to link")
		return errors.Wrap(err, "Unable to add IPv6 addr to link")
	}

	var defaultRoutes []netlink.Route
	for {
		defaultRoutes, err = nsHandle.RouteGet(net.ParseIP("2001:DB8::1"))
		if err == nil {
			break
		}

		if err != unix.ESRCH && err != unix.ENETUNREACH {
			logger.G(ctx).WithError(err).Error("Unable to resolve default route")
			return fmt.Errorf("Unable to resolve default route: %w", err)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("Could not resolve default route: %w", err)
		case <-time.After(100 * time.Millisecond):
		}
	}

	if len(defaultRoutes) != 1 {
		return fmt.Errorf("Got unexpected number of default routes: %d", len(defaultRoutes))
	}

	logger.G(ctx).WithField("defaultRoutes", defaultRoutes).Debug("Got default route")

	for _, route := range assignment.Routes {
		if route.Family != vpcapi.AssignIPResponseV3_Route_IPv6 {
			continue
		}

		_, routeNet, err := net.ParseCIDR(route.Destination)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Could not parse route")
			return fmt.Errorf("Could not parse route CIDR (%s): %w", route.Destination, err)
		}

		newRoute := netlink.Route{
			Gw:        defaultRoutes[0].Gw,
			Src:       new6IP.IP,
			LinkIndex: link.Attrs().Index,
			Dst:       routeNet,
			MTU:       int(route.Mtu),
			// We use the metric 128. The PD / RA based routes have a metric of 128.
			Priority: 128,
		}
		// RA may have already installed a route, therefore we need to use route replace.
		err = nsHandle.RouteReplace(&newRoute)
		if err != nil {
			logger.G(ctx).WithField("route", route).WithError(err).Error("Unable to add route to link")
			return fmt.Errorf("Unable to add route %v to link due to: %w", route, err)
		}
	}

	return nil
}

type bpfAttrMapOpElem struct {
	mapFd uint32
	pad0  [4]byte //nolint:unused,structcheck
	key   uint64
	value uint64
	flags uint64
}

type bpfAttrObjOp struct {
	pathname uint64
	fd       uint32  //nolint:unused,structcheck
	pad0     [4]byte //nolint:unused,structcheck
}

func updateBPFMap(ctx context.Context, mapName string, key []byte, value uint16) error {
	path := []byte("/sys/fs/bpf//tc/globals/" + mapName + "\000")
	openAttrObjOp := bpfAttrObjOp{
		pathname: uint64(uintptr(unsafe.Pointer(&path[0]))),
	}

	fd, _, err := unix.Syscall(
		unix.SYS_BPF,
		unix.BPF_OBJ_GET,
		uintptr(unsafe.Pointer(&openAttrObjOp)),
		unsafe.Sizeof(openAttrObjOp),
	)
	if err != 0 {
		return errors.Wrap(err, "Cannot open BPF Map")
	}
	defer unix.Close(int(fd))
	runtime.KeepAlive(path)

	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(unsafe.Pointer(&key[0]))),
		value: uint64(uintptr(unsafe.Pointer(&value))),
		flags: 0,
	}
	_, _, err = unix.Syscall(
		unix.SYS_BPF,
		unix.BPF_MAP_UPDATE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
	if err != 0 {
		return errors.Wrapf(err, "Unable to update element for map with file descriptor %d", fd)
	}
	runtime.KeepAlive(uba)
	return nil
}

func updateBPFMaps(ctx context.Context, assignment *vpcapi.AssignIPResponseV3) error {
	if assignment.Ipv4Address != nil {
		if err := updateBPFMap(ctx, "ipv4_map", ipv4key(assignment), uint16(assignment.ClassId)); err != nil {
			return err
		}
	}

	if assignment.Ipv6Address != nil {
		if err := updateBPFMap(ctx, "ipv6_map", ipv6key(assignment), uint16(assignment.ClassId)); err != nil {
			return err
		}
	}

	return nil
}

func setupHTBClasses(ctx context.Context, bandwidth *vpcapi.AssignIPResponseV3_Bandwidth, mtu int, allocationIndex uint16, trunkENIMac string) error {
	trunkENI, err := setup2.GetLinkByMac(trunkENIMac)
	if err != nil {
		return err
	}

	ifbIngress, err := netlink.LinkByName(vpc.IngressIFB)
	if err != nil {
		return err
	}

	err = setupClass(ctx, bandwidth, mtu, allocationIndex, trunkENI)
	if err != nil {
		return err
	}
	err = setupSubqdisc(ctx, allocationIndex, trunkENI, uint32(mtu))
	if err != nil {
		return err
	}

	err = setupClass(ctx, bandwidth, mtu, allocationIndex, ifbIngress)
	if err != nil {
		return err
	}
	return setupSubqdisc(ctx, allocationIndex, ifbIngress, uint32(mtu))
}

func setupClass(ctx context.Context, assignmentBandwidth *vpcapi.AssignIPResponseV3_Bandwidth, mtu int, allocationIndex uint16, link netlink.Link) error {
	classattrs := netlink.ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.MakeHandle(1, 1),
		// We assume that
		Handle: netlink.MakeHandle(1, allocationIndex),
	}

	bandwidth := assignmentBandwidth.Bandwidth
	ceil := assignmentBandwidth.Burst
	bytespersecond := float64(bandwidth) / 8.0
	ceilbytespersecond := float64(ceil) / 8.0
	htbclassattrs := netlink.HtbClassAttrs{
		Rate:    bandwidth,
		Ceil:    ceil,
		Buffer:  uint32(math.Ceil(bytespersecond/netlink.Hz()+float64(mtu)) + 1),
		Cbuffer: uint32(math.Ceil(ceilbytespersecond/netlink.Hz()+10*float64(mtu)) + 1),
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

func setupSubqdisc(ctx context.Context, allocationIndex uint16, link netlink.Link, mtu uint32) error {

	// The qdisc wasn't found, add it
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(allocationIndex, 0),
		Parent:    netlink.MakeHandle(1, allocationIndex),
	}
	qdisc := netlink.NewFqCodel(attrs)
	// We add some overhead here for framing
	qdisc.Quantum = mtu + framingOverhead

	err := netlink.QdiscAdd(qdisc)
	if err != nil && err != unix.EEXIST {
		return err
	}

	return nil
}

func DoTeardownContainer(ctx context.Context, assignment *vpcapi.AssignIPResponseV3, netnsfd int) error {
	var result *multierror.Error
	nsHandle, err := netlink.NewHandleAt(netns.NsHandle(netnsfd))
	if err != nil {
		err = errors.Wrap(err, "Could not open handle to netnsfd")
		result = multierror.Append(result, err)
	} else {
		link, err := nsHandle.LinkByName("eth0")
		if err != nil {
			_, ok := err.(*netlink.LinkNotFoundError)
			if !ok {
				err = errors.Wrap(err, "Could not find link eth0 in container network namespace")
				result = multierror.Append(result, err)
			} else {
				logger.G(ctx).WithError(err).Warning("eth0 not found in container on get link by name")
			}
		} else {
			linkDelErr := nsHandle.LinkDel(link)
			if linkDelErr != nil {
				_, ok := linkDelErr.(*netlink.LinkNotFoundError)
				if !ok {
					result = multierror.Append(result, linkDelErr)
				} else {
					logger.G(ctx).WithError(err).Warning("eth0 not found in container on delete")
				}
			}
		}
		nsHandle.Delete()
	}

	result = multierror.Append(result, TeardownNetwork(ctx, assignment))

	return result.ErrorOrNil()
}

func TeardownNetwork(ctx context.Context, assignment *vpcapi.AssignIPResponseV3) error {
	var result *multierror.Error
	// Removing the classes automatically removes the qdiscs
	trunkENI, err := setup2.GetLinkByMac(assignment.TrunkNetworkInterface.MacAddress)
	if err == nil {
		err = removeClass(ctx, uint16(assignment.ClassId), trunkENI)
		if err != nil && !isClassNotFound(err) {
			err = errors.Wrap(err, "Cannot remove class from trunk ENI")
			result = multierror.Append(result, err)
		}
	} else {
		err = errors.Wrap(err, "Unable to find trunk ENI")
		result = multierror.Append(result, err)
		logger.G(ctx).WithError(err).Warning("Unable to find trunk eni, during deallocation")
	}

	ifbIngress, err := netlink.LinkByName(vpc.IngressIFB)
	if err == nil {
		err = removeClass(ctx, uint16(assignment.ClassId), ifbIngress)
		if err != nil && !isClassNotFound(err) {
			err = errors.Wrap(err, "Cannot remove class from ingress IFB")
			result = multierror.Append(result, err)
		}
	} else {
		err = errors.Wrap(err, "Unable to find ifb ingress ENI")
		result = multierror.Append(result, err)
		logger.G(ctx).WithError(err).Warning("Unable to find ifb ingress, during deallocation")
	}

	result = multierror.Append(result, deleteFromBPFMaps(ctx, assignment))
	return result.ErrorOrNil()
}
func deleteFromBPFMaps(ctx context.Context, assignment *vpcapi.AssignIPResponseV3) error {
	var result *multierror.Error
	result = multierror.Append(result, deleteFromIPv4BPFMap(ctx, assignment))
	result = multierror.Append(result, deleteFromIPv6BPFMap(ctx, assignment))
	return result.ErrorOrNil()
}

func deleteFromIPv4BPFMap(ctx context.Context, assignment *vpcapi.AssignIPResponseV3) error {
	if assignment.Ipv4Address == nil {
		return nil
	}

	path := []byte("/sys/fs/bpf//tc/globals/ipv4_map\000")
	openAttrObjOp := bpfAttrObjOp{
		pathname: uint64(uintptr(unsafe.Pointer(&path[0]))),
	}

	fd, _, err := unix.Syscall(
		unix.SYS_BPF,
		unix.BPF_OBJ_GET,
		uintptr(unsafe.Pointer(&openAttrObjOp)),
		unsafe.Sizeof(openAttrObjOp),
	)
	if err != 0 {
		err2 := errors.Wrap(err, "Cannot open BPF Map ipv4_map")
		logger.G(ctx).WithError(err2).Error("Cannot get ipv4_map")
		return err2
	}
	defer unix.Close(int(fd))
	runtime.KeepAlive(path)

	key := ipv4key(assignment)
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(unsafe.Pointer(&key[0]))),
	}
	_, _, err = unix.Syscall(
		unix.SYS_BPF,
		unix.BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
	if err == unix.ENOENT {
		err := errors.Wrap(err, "Unable to delete element for ipv4 map (notfound) ")
		logger.G(ctx).WithError(err).WithField("ip", assignment.Ipv4Address.Address.Address).WithField("classid", assignment.ClassId).WithField("vlanid", assignment.VlanId).Error("Element not found")
		return err
	} else if err != 0 {
		logger.G(ctx).WithError(err).Errorf("Unable to delete element for ipv4 map with file descriptor %d", fd)
		err2 := errors.Wrap(err, "Unable to delete element for ipv4 map")
		return err2
	}
	runtime.KeepAlive(uba)

	return nil
}
func deleteFromIPv6BPFMap(ctx context.Context, assignment *vpcapi.AssignIPResponseV3) error {
	if assignment.Ipv6Address == nil {
		return nil
	}
	ip := net.ParseIP(assignment.Ipv6Address.Address.Address).To16()
	if len(ip) != 16 {
		panic("Length of IP is not 16")
	}

	path := []byte("/sys/fs/bpf//tc/globals/ipv6_map\000")
	openAttrObjOp := bpfAttrObjOp{
		pathname: uint64(uintptr(unsafe.Pointer(&path[0]))),
	}

	fd, _, errno := unix.Syscall(
		unix.SYS_BPF,
		unix.BPF_OBJ_GET,
		uintptr(unsafe.Pointer(&openAttrObjOp)),
		unsafe.Sizeof(openAttrObjOp),
	)
	if errno != 0 {
		err := errors.Wrap(errno, "Cannot open BPF Map ipv6_map")
		logger.G(ctx).WithError(err).Error("Cannot get ipv6_map")
		return err
	}
	defer unix.Close(int(fd))
	runtime.KeepAlive(path)

	key := ipv6key(assignment)
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(unsafe.Pointer(&key[0]))),
	}
	_, _, errno = unix.Syscall(
		unix.SYS_BPF,
		unix.BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
	if errno == unix.ENOENT {
		err := errors.Wrap(errno, "Unable to delete element for ipv6 map (notfound)")
		logger.G(ctx).WithError(err).WithField("ip", assignment.Ipv6Address.Address.Address).WithField("classid", assignment.ClassId).WithField("vlanid", assignment.VlanId).Error("Element not found")
		return err
	} else if errno != 0 {
		logger.G(ctx).WithError(errors.Wrapf(errno, "Unable to delete element for map with file descriptor %d", fd)).Error()
		err := errors.Wrap(errno, "Unable to delete element for ipv6 map")
		return err
	}
	runtime.KeepAlive(uba)
	return nil
}

func ipv6key(assignment *vpcapi.AssignIPResponseV3) []byte {
	if assignment.Ipv6Address == nil {
		return nil
	}
	buf := make([]byte, 20)
	binary.LittleEndian.PutUint16(buf, uint16(assignment.VlanId))
	ip := net.ParseIP(assignment.Ipv6Address.Address.Address).To16()
	if len(ip) != 16 {
		panic("Length of IP is not 16")
	}
	copy(buf[4:], ip)
	return buf
}

func ipv4key(assignment *vpcapi.AssignIPResponseV3) []byte {
	if assignment.Ipv4Address == nil {
		return nil
	}
	buf := make([]byte, 8)

	binary.LittleEndian.PutUint16(buf, uint16(assignment.VlanId))
	ip := net.ParseIP(assignment.Ipv4Address.Address.Address).To4()
	if len(ip) != 4 {
		panic("Length of IP is not 4")
	}
	copy(buf[4:], ip)
	return buf
}

type classNotFound struct {
	handle uint16
	link   netlink.Link
}

func (c *classNotFound) Error() string {
	return fmt.Sprintf("Unable to find class %d on link %v", c.handle, c.link)
}

func (c *classNotFound) Is(target error) bool {
	_, ok := target.(*classNotFound)
	return ok
}

func isClassNotFound(err error) bool {
	return errors.Is(err, &classNotFound{})
}

func removeClass(ctx context.Context, handle uint16, link netlink.Link) error {
	classes, err := netlink.ClassList(link, netlink.MakeHandle(1, 1))
	if err != nil {
		logger.G(ctx).Errorf("Unable to list classes on link %v because %v", link, err)
		err = errors.Wrapf(err, "Unable to list classes on link %v", link)
		return err
	}
	for _, class := range classes {
		htbClass := class.(*netlink.HtbClass)
		logger.G(ctx).Debug("Class: ", class)
		logger.G(ctx).Debug("Class: ", class.Attrs())

		if htbClass.Attrs().Handle == netlink.MakeHandle(1, handle) {
			err = netlink.ClassDel(class)
			if err != nil {
				logger.G(ctx).WithError(err).Warning("Unable to remove class")
				err = errors.Wrap(err, "Unable to remove class")
				return err
			}
			return nil
		}
	}

	logger.G(ctx).Warning("Unable to find class for container")
	return &classNotFound{handle: handle, link: link}
}

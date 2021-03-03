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
	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/apparentlymart/go-cidr/cidr"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/mdlayher/ndp"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	networkSetupWait = 30 * time.Second
)

var (
	errNoRoutesReceived = errors.New("No routes receives from Titus VPC Service")
	errNoDefaultRoute   = errors.New("No default route installed")
)

func getBranchLink(ctx context.Context, allocations types.Allocation) (netlink.Link, error) {
	trunkLink, err := setup2.GetLinkByMac(allocations.TrunkENIMAC)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot find trunk link")
	}

	vlanLinkName := fmt.Sprintf("vlan%d", allocations.VlanID)
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
				VlanId:       allocations.VlanID,
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

	if vlanLink.Attrs().HardwareAddr.String() != allocations.BranchENIMAC {
		mac, err := net.ParseMAC(allocations.BranchENIMAC)
		if err != nil {
			return nil, errors.Wrapf(err, "Cannot parse mac %q", allocations.BranchENIMAC)
		}
		err = netlink.LinkSetHardwareAddr(vlanLink, mac)
		if err != nil {
			return nil, errors.Wrap(err, "Cannot update branch ENI mac")
		}
	}

	return vlanLink, nil
}

func getNsFd(netNS interface{}) (int, bool, error) {
	netnsfd := 0
	isTransLink := false
	switch v := netNS.(type) {
	case int:
		netnsfd = v
	case string:
		isTransLink = true
		nsHdl, err := netns.NewNamed(v)
		if err != nil {
			return netnsfd, false, err
		}
		netnsfd = int(nsHdl)
	}
	return netnsfd, isTransLink, nil
}

func DoSetupContainer(ctx context.Context, netNS interface{}, withTrans bool, bandwidth, ceil uint64, allocation types.Allocation) error {
	branchLink, err := getBranchLink(ctx, allocation)
	if err != nil {
		return err
	}

	netnsfd, isTransLink, err := getNsFd(netNS)
	if err != nil {
		return err
	}

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

	return configureLink(ctx, nsHandle, newLink, isTransLink, withTrans, bandwidth, ceil, allocation, netnsfd)
}

func addIPv4AddressAndRoutes(ctx context.Context, nsHandle *netlink.Handle, link netlink.Link, address *vpcapi.UsableAddress, routes []*vpcapi.AssignIPResponseV3_Route) (uint64, error) {
	mask := net.CIDRMask(int(address.PrefixLength), 32)
	ip := net.ParseIP(address.Address.Address)

	ctx = logger.WithField(logger.WithField(ctx, "mask", mask), "ip", address.Address.Address)
	logger.G(ctx).Debug("Adding IPV4 address and route")
	// The netlink package appears to automatically calculate broadcast
	ipnet := &net.IPNet{IP: ip, Mask: mask}
	new4Addr := netlink.Addr{
		IPNet: ipnet,
	}
	err := nsHandle.AddrAdd(link, &new4Addr)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to add IPv4 addr to link")
		return 0, errors.Wrap(err, "Unable to add IPv4 addr to link")
	}

	gateway := cidr.Inc(ip.Mask(mask))
	var mtu uint64
	if len(routes) == 0 {
		return 0, errNoRoutesReceived
	}
	for _, route := range routes {
		if route.Family != vpcapi.AssignIPResponseV3_Route_IPv4 {
			continue
		}
		logger.G(ctx).WithField("route", route).Debug("Adding route")
		_, routeNet, err := net.ParseCIDR(route.Destination)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Could not parse route")
			return 0, fmt.Errorf("Could not parse route CIDR (%s): %w", route.Destination, err)
		}
		if routeNet.String() == "0.0.0.0/0" {
			mtu = uint64(route.Mtu)
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
			return 0, fmt.Errorf("Unable to add route %v to link due to: %w", route, err)
		}
	}

	if mtu == 0 {
		return 0, errNoDefaultRoute
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
		return 0, errors.Wrap(err, "Unable to add gateway route to link")
	}

	// Removing this forces all traffic through the gateway, which is the AWS virtual gateway / phantom router
	// this is beneficial for two reasons:
	// 1. No ARP needed because you only ever need to learn the ARP / neighbor entry of the default gateway
	// 2. It means that certain security things are enforced
	oldLinkRoute := netlink.Route{
		Protocol:  unix.RTPROT_UNSPEC,
		Dst:       &net.IPNet{IP: ip.Mask(mask), Mask: mask},
		LinkIndex: link.Attrs().Index,
		Src:       ip,
		Table:     unix.RT_TABLE_MAIN,
		Scope:     unix.RT_SCOPE_NOWHERE,
		Type:      unix.RTN_UNSPEC,
	}
	logger.G(ctx).WithField("route", oldLinkRoute).Debug("Deleting link route")

	err = nsHandle.RouteDel(&oldLinkRoute)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to delete route on link")
		return 0, errors.Wrap(err, "Unable to add delete existing 'link' route to link")
	}

	return mtu, nil
}

func configureLink(ctx context.Context, nsHandle *netlink.Handle, link netlink.Link, isTransLink bool, withTrans bool, bandwidth, ceil uint64, allocation types.Allocation, netnsfd int) error {
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

	defaultMTU := uint64(0)
	if !withTrans || (withTrans && isTransLink) {
		defaultMTU, err = addIPv4AddressAndRoutes(ctx, nsHandle, link, allocation.IPV4Address, allocation.Routes)
		if err != nil {
			return err
		}
	}

	if allocation.IPV6Address != nil && !(withTrans && isTransLink) {
		err = addIPv6AddressAndRoutes(ctx, allocation, nsHandle, link, netnsfd)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Unable to add IPv6 address")
			return fmt.Errorf("Unable to setup IPv6 address: %w", err)
		}
	}

	err = updateBPFMaps(ctx, allocation)
	if err != nil {
		return err
	}

	err = setupHTBClasses(ctx, bandwidth, ceil, defaultMTU, allocation.AllocationIndex, allocation.TrunkENIMAC)
	if err != nil {
		return err
	}

	return nil
}

func addIPv6AddressAndRoutes(ctx context.Context, allocation types.Allocation, nsHandle *netlink.Handle, link netlink.Link, netnsfd int) error {
	ctx, cancel := context.WithTimeout(ctx, networkSetupWait)
	defer cancel()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Amazon only gives out /128s
	new6IP := net.IPNet{IP: net.ParseIP(allocation.IPV6Address.Address.Address), Mask: net.CIDRMask(128, 128)}
	new6Addr := netlink.Addr{
		// TODO (Sargun): Check IP Mask setting.
		IPNet: &new6IP,
		Flags: unix.IFA_F_PERMANENT | unix.IFA_F_NODAD,
		Scope: unix.RT_SCOPE_UNIVERSE,
	}
	err := nsHandle.AddrAdd(link, &new6Addr)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to add IPv6 addr to link")
		return errors.Wrap(err, "Unable to add IPv6 addr to link")
	}

	var linkLocalAddr netlink.Addr
	for {
		// We need *a* permanent address
		addrs, err := nsHandle.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			return fmt.Errorf("Cannot get addrs: %w", err)
		}

		for _, addr := range addrs {
			if addr.Scope == unix.RT_SCOPE_LINK {
				linkLocalAddr = addr
				goto out
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("Did not find permanent link-local address in set: %v: %w", addrs, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}

out:
	origns, err := netns.Get()
	defer origns.Close()
	if err != nil {
		return fmt.Errorf("Could not get current net ns: %w", err)
	}

	err = netns.Set(netns.NsHandle(netnsfd))
	if err != nil {
		return fmt.Errorf("Could not switch net ns: %w", err)
	}

	networkInterface, err := net.InterfaceByName("eth0")
	if err != nil {
		return fmt.Errorf("Could not get network interface eth0: %w", err)
	}

	conn, _, err := ndp.Dial(networkInterface, ndp.Addr(linkLocalAddr.IP.String()))
	if err != nil {
		return fmt.Errorf("Unable to dial NDP conn: %w", err)
	}
	defer conn.Close()

	var filter ipv6.ICMPFilter
	filter.SetAll(true)
	filter.Accept(ipv6.ICMPTypeRouterAdvertisement)
	err = conn.SetICMPFilter(&filter)
	if err != nil {
		return fmt.Errorf("Unable to setup ICMP filter %v: %w", filter, err)
	}

	m := &ndp.RouterSolicitation{
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      networkInterface.HardwareAddr,
			},
		},
	}

	/* Poll for the router */
	var routerAddr net.IP
	for {
		err = ctx.Err()
		if err != nil {
			return fmt.Errorf("Context complete before NDP finished: %w", err)
		}

		err = conn.WriteTo(m, &ipv6.ControlMessage{
			HopLimit: 1,
			Src:      linkLocalAddr.IP,
			Dst:      net.IPv6linklocalallrouters,
			IfIndex:  networkInterface.Index,
		}, net.IPv6linklocalallrouters)
		if err != nil {
			return fmt.Errorf("Could not write router solicitication message: %w", err)
		}

		// TODO: Maybe don't hardcode this?
		deadline := time.Now().Add(time.Second)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		err = conn.SetReadDeadline(deadline)
		if err != nil {
			return fmt.Errorf("Unable to set read deadline to %v: %w", deadline, err)
		}

		srcMsg, srcCM, srcAddr, err := conn.ReadFrom()
		if err == nil {
			// We're guaranteed only to get router advertisements because of the filter we setup
			logger.G(ctx).WithFields(map[string]interface{}{
				"msg":     fmt.Sprintf("%+v", srcMsg),
				"srcCM":   fmt.Sprintf("%+v", srcCM),
				"srcAddr": srcAddr,
			}).Info("Received router advertisement")
			routerAddr = srcAddr
			break
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			logger.G(ctx).Debug("I/O read timeout")
			continue
		}
		return fmt.Errorf("Could not read router soliticiation response / router advertisement: %w", err)
	}

	for _, route := range allocation.Routes {
		if route.Family != vpcapi.AssignIPResponseV3_Route_IPv6 {
			continue
		}
		logger.G(ctx).WithField("route", route).Debug("Adding route")
		_, routeNet, err := net.ParseCIDR(route.Destination)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Could not parse route")
			return fmt.Errorf("Could not parse route CIDR (%s): %w", route.Destination, err)
		}

		newRoute := netlink.Route{
			Gw:        routerAddr,
			Src:       new6IP.IP,
			LinkIndex: link.Attrs().Index,
			Dst:       routeNet,
			MTU:       int(route.Mtu),
		}
		// RA may have already installed a route, therefore we need to use route replace.
		err = nsHandle.RouteReplace(&newRoute)
		if err != nil {
			logger.G(ctx).WithField("route", route).WithError(err).Error("Unable to add route to link")
			return fmt.Errorf("Unable to add route %v to link due to: %w", route, err)
		}
	}

	err = netns.Set(origns)
	if err != nil {
		return fmt.Errorf("Could not set NS back to original net ns: %w", err)
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

func updateBPFMaps(ctx context.Context, allocation types.Allocation) error {
	if allocation.IPV4Address != nil {
		buf := make([]byte, 8)

		binary.LittleEndian.PutUint16(buf, uint16(allocation.VlanID))
		ip := net.ParseIP(allocation.IPV4Address.Address.Address).To4()
		if len(ip) != 4 {
			panic("Length of IP is not 4")
		}
		copy(buf[4:], ip)
		if err := updateBPFMap(ctx, "ipv4_map", buf, allocation.AllocationIndex); err != nil {
			return err
		}
	}

	if allocation.IPV6Address != nil {
		buf := make([]byte, 20)
		binary.LittleEndian.PutUint16(buf, uint16(allocation.VlanID))
		ip := net.ParseIP(allocation.IPV6Address.Address.Address).To16()
		if len(ip) != 16 {
			panic("Length of IP is not 16")
		}

		copy(buf[4:], ip)
		if err := updateBPFMap(ctx, "ipv6_map", buf, allocation.AllocationIndex); err != nil {
			return err
		}
	}

	return nil
}

func setupHTBClasses(ctx context.Context, bandwidth, ceil, mtu uint64, allocationIndex uint16, trunkENIMac string) error {
	trunkENI, err := setup2.GetLinkByMac(trunkENIMac)
	if err != nil {
		return err
	}

	ifbIngress, err := netlink.LinkByName(vpc.IngressIFB)
	if err != nil {
		return err
	}

	err = setupClass(ctx, bandwidth, ceil, mtu, allocationIndex, trunkENI)
	if err != nil {
		return err
	}
	err = setupSubqdisc(ctx, allocationIndex, trunkENI, uint32(mtu))
	if err != nil {
		return err
	}

	err = setupClass(ctx, bandwidth, ceil, mtu, allocationIndex, ifbIngress)
	if err != nil {
		return err
	}
	return setupSubqdisc(ctx, allocationIndex, ifbIngress, uint32(mtu))
}

func setupClass(ctx context.Context, bandwidth, ceil, mtu uint64, allocationIndex uint16, link netlink.Link) error {
	classattrs := netlink.ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.MakeHandle(1, 1),
		// We assume that
		Handle: netlink.MakeHandle(1, allocationIndex),
	}

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
	qdisc.Quantum = mtu

	err := netlink.QdiscAdd(qdisc)
	if err != nil && err != unix.EEXIST {
		return err
	}

	return nil
}

func DoTeardownContainer(ctx context.Context, allocation types.Allocation, netNS interface{}) error {
	var result *multierror.Error
	netnsfd, _, err := getNsFd(netNS)
	if err != nil {
		err = errors.Wrap(err, "Could not get netnsfd from namespace")
		result = multierror.Append(result, err)
		return result.ErrorOrNil()
	}
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

	result = multierror.Append(result, TeardownNetwork(ctx, allocation))

	return result.ErrorOrNil()
}

func TeardownNetwork(ctx context.Context, allocation types.Allocation) error {
	var result *multierror.Error
	// Removing the classes automatically removes the qdiscs
	trunkENI, err := setup2.GetLinkByMac(allocation.TrunkENIMAC)
	if err == nil {
		err = removeClass(ctx, allocation.AllocationIndex, trunkENI)
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
		err = removeClass(ctx, allocation.AllocationIndex, ifbIngress)
		if err != nil && !isClassNotFound(err) {
			err = errors.Wrap(err, "Cannot remove class from ingress IFB")
			result = multierror.Append(result, err)
		}
	} else {
		err = errors.Wrap(err, "Unable to find ifb ingress ENI")
		result = multierror.Append(result, err)
		logger.G(ctx).WithError(err).Warning("Unable to find ifb ingress, during deallocation")
	}

	result = multierror.Append(result, deleteFromBPFMaps(ctx, allocation))
	return result.ErrorOrNil()
}
func deleteFromBPFMaps(ctx context.Context, allocation types.Allocation) error {
	var result *multierror.Error
	result = multierror.Append(result, deleteFromIPv4BPFMap(ctx, allocation))
	result = multierror.Append(result, deleteFromIPv6BPFMap(ctx, allocation))
	return result.ErrorOrNil()
}

func deleteFromIPv4BPFMap(ctx context.Context, allocation types.Allocation) error {
	if allocation.IPV4Address == nil {
		return nil
	}
	buf := make([]byte, 8)

	binary.LittleEndian.PutUint16(buf, uint16(allocation.VlanID))
	ip := net.ParseIP(allocation.IPV4Address.Address.Address).To4()
	if len(ip) != 4 {
		panic("Length of IP is not 4")
	}
	copy(buf[4:], ip)
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

	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(unsafe.Pointer(&buf[0]))),
	}
	_, _, err = unix.Syscall(
		unix.SYS_BPF,
		unix.BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
	if err != unix.ENOENT && err != 0 {
		logger.G(ctx).WithError(err).Errorf("Unable to delete element for ipv4 map with file descriptor %d", fd)
		err2 := errors.Wrap(err, "Unable to delete element for ipv4 map")
		return err2
	}
	runtime.KeepAlive(uba)

	return nil
}
func deleteFromIPv6BPFMap(ctx context.Context, allocation types.Allocation) error {
	if allocation.IPV6Address == nil {
		return nil
	}
	buf := make([]byte, 20)
	binary.LittleEndian.PutUint16(buf, uint16(allocation.VlanID))
	ip := net.ParseIP(allocation.IPV6Address.Address.Address).To16()
	if len(ip) != 16 {
		panic("Length of IP is not 16")
	}

	copy(buf[4:], ip)

	path := []byte("/sys/fs/bpf//tc/globals/ipv6_map\000")
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
		err2 := errors.Wrap(err, "Cannot open BPF Map ipv6_map")
		logger.G(ctx).WithError(err2).Error("Cannot get ipv6_map")
		return err2
	}
	defer unix.Close(int(fd))
	runtime.KeepAlive(path)

	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(unsafe.Pointer(&buf[0]))),
	}
	_, _, err = unix.Syscall(
		unix.SYS_BPF,
		unix.BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
	if err != unix.ENOENT && err != 0 {
		logger.G(ctx).WithError(errors.Wrapf(err, "Unable to delete element for map with file descriptor %d", fd)).Error()
		err2 := errors.Wrap(err, "Unable to delete element for ipv4 map")
		return err2
	}
	runtime.KeepAlive(uba)
	return nil
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

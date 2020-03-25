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

	"github.com/hashicorp/go-multierror"

	"github.com/Netflix/titus-executor/vpc/tool/shared"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	networkSetupWait = 30 * time.Second
)

var (
	errAddressSetupTimeout = errors.New("IPv6 address setup timed out")
)

func getBranchLink(ctx context.Context, allocations types.Allocation) (netlink.Link, error) {
	trunkLink, err := shared.GetLinkByMac(allocations.TrunkENIMAC)
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

func DoSetupContainer(ctx context.Context, netnsfd int, bandwidth, ceil uint64, jumbo bool, allocation types.Allocation) error {
	branchLink, err := getBranchLink(ctx, allocation)
	if err != nil {
		return err
	}

	nsHandle, err := netlink.NewHandleAt(netns.NsHandle(netnsfd))
	if err != nil {
		return err
	}
	defer nsHandle.Delete()

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
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

	var mtu *int
	if !jumbo {
		nonJumboMTU := 1500
		mtu = &nonJumboMTU
	}

	return configureLink(ctx, nsHandle, newLink, bandwidth, ceil, mtu, allocation)
}

func addIPv4AddressAndRoute(ctx context.Context, nsHandle *netlink.Handle, link netlink.Link, mtu *int, address *vpcapi.UsableAddress) error {
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
		return errors.Wrap(err, "Unable to add IPv4 addr to link")
	}

	gateway := cidr.Inc(ip.Mask(mask))
	logger.G(ctx).WithField("gateway", gateway).Debug("Adding default route")
	newRoute := netlink.Route{
		Gw:        gateway.To4(),
		Src:       ip,
		LinkIndex: link.Attrs().Index,
	}
	if mtu != nil {
		newRoute.MTU = *mtu
	}
	err = nsHandle.RouteAdd(&newRoute)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to add route to link")
		return errors.Wrap(err, "Unable to add default route to link")
	}

	logger.G(ctx).WithField("gateway", gateway).Debug("Adding gateway route")
	newRoute = netlink.Route{
		Dst:       &net.IPNet{IP: gateway, Mask: net.CIDRMask(32, 32)},
		Src:       ip,
		LinkIndex: link.Attrs().Index,
		Scope:     unix.RT_SCOPE_LINK,
	}
	err = nsHandle.RouteAdd(&newRoute)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to add route to link")
		return errors.Wrap(err, "Unable to add gateway route to link")
	}

	newRoute = netlink.Route{
		Protocol:  unix.RTPROT_UNSPEC,
		Dst:       &net.IPNet{IP: ip.Mask(mask), Mask: mask},
		LinkIndex: link.Attrs().Index,
		Src:       ip,
		Table:     unix.RT_TABLE_MAIN,
		Scope:     unix.RT_SCOPE_NOWHERE,
		Type:      unix.RTN_UNSPEC,
	}
	logger.G(ctx).WithField("route", newRoute).Debug("Deleting link route")

	err = nsHandle.RouteDel(&newRoute)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to delete route on link")
		return errors.Wrap(err, "Unable to add delete existing 'link' route to link")
	}

	return nil
}

func configureLink(ctx context.Context, nsHandle *netlink.Handle, link netlink.Link, bandwidth, ceil uint64, mtu *int, allocation types.Allocation) error {
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

	if allocation.IPV6Address != nil {
		// Amazon only gives out /128s
		new6Addr := netlink.Addr{
			// TODO (Sargun): Check IP Mask setting.
			IPNet: &net.IPNet{IP: net.ParseIP(allocation.IPV6Address.Address.Address), Mask: net.CIDRMask(128, 128)},
		}
		err = nsHandle.AddrAdd(link, &new6Addr)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Unable to add IPv6 addr to link")
			return errors.Wrap(err, "Unable to add IPv6 addr to link")
		}
	}

	err = addIPv4AddressAndRoute(ctx, nsHandle, link, mtu, allocation.IPV4Address)
	if err != nil {
		return err
	}

	err = updateBPFMaps(ctx, allocation)
	if err != nil {
		return err
	}

	linkMTUOrSmaller := link.Attrs().MTU
	if mtu != nil {
		linkMTUOrSmaller = *mtu
	}
	err = setupHTBClasses(ctx, bandwidth, ceil, uint64(linkMTUOrSmaller), allocation.AllocationIndex, allocation.TrunkENIMAC)
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
	trunkENI, err := shared.GetLinkByMac(trunkENIMac)
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

func DoTeardownContainer(ctx context.Context, allocation types.Allocation, netnsfd int) error {
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

	result = multierror.Append(result, TeardownNetwork(ctx, allocation))

	return result.ErrorOrNil()
}

func TeardownNetwork(ctx context.Context, allocation types.Allocation) error {
	var result *multierror.Error
	// Removing the classes automatically removes the qdiscs
	trunkENI, err := shared.GetLinkByMac(allocation.TrunkENIMAC)
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

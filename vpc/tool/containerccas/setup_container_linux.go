// +build linux

package containerccas

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func getVLANLink(ctx context.Context, assignment *vpcapi.CCAS) (netlink.Link, error) {
	trunkLink, err := netlink.LinkByName("eth0")
	if err != nil {
		return nil, errors.Wrap(err, "Cannot find eth0 link")
	}

	vlanLinkName := fmt.Sprintf("vlan%d", assignment.Vlan)
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
				VlanId:       int(assignment.Vlan),
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
		err = netlink.LinkSetUp(vlanLink)
		if err != nil {
			return nil, errors.Wrap(err, "Cannot set vlan link by up")
		}
	}

	return vlanLink, nil
}

func DoSetupContainer(ctx context.Context, netnsfd int, allocation *vpcapi.CCAS) error {
	logger.G(ctx).WithField("assignment", allocation.String()).Info("Configuring networking with assignment")
	vlanLink, err := getVLANLink(ctx, allocation)
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
			ParentIndex: vlanLink.Attrs().Index,
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

	return configureLink(ctx, nsHandle, newLink, allocation, netnsfd)
}

func configureLink(ctx context.Context, nsHandle *netlink.Handle, link netlink.Link, allocation *vpcapi.CCAS, netnsfd int) error {
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

	mask := net.CIDRMask(int(allocation.Ipv4Address.PrefixLength), 32)
	ip := net.ParseIP(allocation.Ipv4Address.Address.Address)
	ipnet := &net.IPNet{IP: ip, Mask: mask}
	new4Addr := netlink.Addr{
		IPNet: ipnet,
	}

	err = nsHandle.AddrAdd(link, &new4Addr)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to add IPv4 addr to link")
		return errors.Wrap(err, "Unable to add IPv4 addr to link")
	}

	_, dst, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		panic(err)
	}

	gateway := cidr.Inc(ip.Mask(mask))
	newRoute := netlink.Route{
		Gw:        gateway.To4(),
		Src:       ip,
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		// TODO: Consider adding this back?
		//		MTU:       int(route.Mtu),
	}
	err = nsHandle.RouteAdd(&newRoute)
	if err != nil {
		logger.G(ctx).WithField("route", newRoute).WithError(err).Error("Unable to add route to link")
		return fmt.Errorf("Unable to add route %v to link due to: %w", newRoute, err)
	}

	return nil
}

func DoTeardownContainer(ctx context.Context, assignment *vpcapi.CCAS, netnsfd int) error {
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

	return result.ErrorOrNil()
}

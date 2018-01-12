// +build linux

package setup

import (
	"bytes"

	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/bpf/filter"
	"github.com/Netflix/titus-executor/vpc/bpfloader"
	"github.com/Netflix/titus-executor/vpc/context"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	rootHtbClass = netlink.MakeHandle(1, 1)
)

type clsAct struct {
	netlink.QdiscAttrs
}

func (c *clsAct) Attrs() *netlink.QdiscAttrs {
	return &c.QdiscAttrs
}

func (c *clsAct) Type() string {
	return "clsact"
}

func configureQdiscs(ctx *context.VPCContext) error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	ifbIngress, err := netlink.LinkByName(vpc.IngressIFB)
	if err != nil {
		return err
	}
	ifbEgress, err := netlink.LinkByName(vpc.EgressIFB)
	if err != nil {
		return err
	}

	networkInterfaces, err := ctx.EC2metadataClientWrapper.Interfaces()
	if err != nil {
		return err
	}

	for _, link := range links {
		if networkInterface, ok := networkInterfaces[link.Attrs().HardwareAddr.String()]; !ok {
			ctx.Logger.Debug("Skipping work on link, as it's not an ENI: ", link)
			continue
		} else if networkInterface.DeviceNumber == 0 {
			continue
		}
		ctx.Logger.Debugf("Configuring link: %+v", link)
		err = configureQdiscsForLink(ctx, link)
		if err != nil {
			return err
		}
		err = configureFiltersForLink(ctx, link, ifbIngress, ifbEgress)
		if err != nil {
			return err
		}
	}
	return nil
}

func configureFiltersForLink(ctx *context.VPCContext, link, ifbIngress, ifbEgress netlink.Link) error {
	egressFilter := netlink.MatchAll{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Priority:  32000,
			Protocol:  unix.ETH_P_ALL,
		},
		Actions: []netlink.Action{
			&netlink.MirredAction{
				ActionAttrs: netlink.ActionAttrs{
					Action: netlink.TC_ACT_STOLEN,
				},
				MirredAction: netlink.TCA_EGRESS_REDIR,
				Ifindex:      ifbEgress.Attrs().Index,
			},
		},
	}
	err := netlink.FilterAdd(&egressFilter)
	if err != nil && err != unix.EEXIST {
		return err
	}

	ingressFilter := netlink.MatchAll{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Priority:  32000,
			Protocol:  unix.ETH_P_ALL,
		},
		Actions: []netlink.Action{
			&netlink.MirredAction{
				ActionAttrs: netlink.ActionAttrs{
					Action: netlink.TC_ACT_STOLEN,
				},
				MirredAction: netlink.TCA_EGRESS_REDIR,
				Ifindex:      ifbIngress.Attrs().Index,
			},
		},
	}
	err = netlink.FilterAdd(&ingressFilter)
	if err != nil && err != unix.EEXIST {
		return err
	}

	return nil

}

func configureQdiscsForLink(ctx *context.VPCContext, link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Attrs().Parent == netlink.HANDLE_CLSACT && qdisc.Type() == "clsact" {
			return nil
		}
	}

	ctx.Logger.Debugf("Setting up qdisc on: %+v", link)
	qdisc := clsAct{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    0xFFFF0000,
		},
	}
	return netlink.QdiscReplace(&qdisc)
}

func setupIFBs(ctx *context.VPCContext) error {
	err := setupIFB(ctx, vpc.IngressIFB, "classifier_ingress")
	if err != nil {
		return err
	}

	return setupIFB(ctx, vpc.EgressIFB, "classifier_egress")
}

func setupIFB(ctx *context.VPCContext, ifbName, filterName string) error {
	link, err := netlink.LinkByName(ifbName)
	if err != nil && err.Error() == "Link not found" {
		ctx.Logger.Info("Adding link: ", ifbName)
		ifb := netlink.Ifb{
			LinkAttrs: netlink.LinkAttrs{
				Name: ifbName,
				// See: https://github.com/containernetworking/cni/pull/199/files
				TxQLen: -1,
				// AWS Upper bound of MTU
				MTU: 9001,
			},
		}
		if err2 := netlink.LinkAdd(&ifb); err2 != nil {
			return err2
		}
		// Retry
		return setupIFB(ctx, ifbName, filterName)
	} else if err != nil {
		return err
	}
	// This is idempotent
	err = netlink.LinkSetUp(link)
	if err != nil {
		return err
	}

	err = setupIFBQdisc(ctx, link)
	if err != nil {
		return err
	}

	return setupIFBBPFFilter(ctx, link, filterName)
}

func setupIFBBPFFilter(ctx *context.VPCContext, link netlink.Link, filterName string) error {
	filterData, err := filter.Asset("filter.o")
	if err != nil {
		return err
	}

	schedProgram, err := bpfloader.GetProgram(bytes.NewReader(filterData), filterName)
	if err != nil {
		return err
	}
	defer func() {
		e := unix.Close(schedProgram)
		if e != nil {
			ctx.Logger.Warning("Cannot close bpf program: ", e)
		}
	}()
	filterattrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.MakeHandle(1, 0),
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_IP,
		Priority:  32000,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           schedProgram,
		Name:         filterName,
		DirectAction: true,
		ClassId:      netlink.MakeHandle(1, 1),
	}
	err = netlink.FilterAdd(filter)
	if err != nil && err != unix.EEXIST {
		return err
	}
	return nil
}

func setupIFBQdisc(ctx *context.VPCContext, link netlink.Link) error {
	err := setupIFBHTBQdisc(ctx, link)
	if err != nil {
		return err
	}
	return setupIFBHTBRootClass(ctx, link)
}
func setupIFBHTBRootClass(ctx *context.VPCContext, link netlink.Link) error {
	classattrs := netlink.ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.HANDLE_ROOT,
		Handle:    rootHtbClass,
	}

	htbclassattrs := netlink.HtbClassAttrs{
		Rate: vpc.GetMaxNetworkbps(ctx.InstanceType),
	}
	class := netlink.NewHtbClass(classattrs, htbclassattrs)
	return netlink.ClassReplace(class)
}

func setupIFBHTBQdisc(ctx *context.VPCContext, link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if _, ok := qdisc.(*netlink.Htb); ok {
			return nil
		}
	}
	// The qdisc wasn't found, add it
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(1, 0),
		Parent:    netlink.HANDLE_ROOT,
	}
	qdisc := netlink.NewHtb(attrs)
	return netlink.QdiscAdd(qdisc)
}

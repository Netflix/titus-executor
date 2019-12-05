// +build linux

package setup2

import (
	"context"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/bpf2/filter"
	"github.com/Netflix/titus-executor/vpc/tool/shared"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	rootHtbClass = netlink.MakeHandle(1, 1)
)

func configureQdiscs(ctx context.Context, provisionInstanceResponse *vpcapi.ProvisionInstanceResponseV2, instanceType string) error {
	ingressIFB, err := setupIngressIFB(ctx)
	if err != nil {
		return err
	}
	trunkInterface, err := shared.GetLinkByMac(provisionInstanceResponse.TrunkNetworkInterface.MacAddress)
	if err != nil {
		return errors.Wrap(err, "Cannot get trunk interface")
	}
	err = addClsActToLink(ctx, trunkInterface)
	if err != nil {
		return errors.Wrap(err, "Cannot add clsact to link")
	}

	/* Add the ingress redirect filter */
	ingressFilter := netlink.MatchAll{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: trunkInterface.Attrs().Index,
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
				Ifindex:      ingressIFB.Attrs().Index,
			},
		},
	}
	err = netlink.FilterAdd(&ingressFilter)
	if err != nil && err != unix.EEXIST {
		return err
	}

	err = setupHTBQdisc(ctx, trunkInterface)
	if err != nil {
		return errors.Wrap(err, "Could not setup HTB Qdisc on trunk interface")
	}
	err = setupHTBQdisc(ctx, ingressIFB)
	if err != nil {
		return errors.Wrap(err, "Could not setup HTB Qdisc on ifb interface")
	}

	err = setupIFBHTBRootClass(ctx, instanceType, trunkInterface)
	if err != nil {
		return errors.Wrap(err, "Could not setup HTB root class on trunk interface")
	}

	err = setupIFBHTBRootClass(ctx, instanceType, ingressIFB)
	if err != nil {
		return errors.Wrap(err, "Could not setup HTB root class on ingress ifb interface")
	}

	err = setupLinkIFBFilter(ctx, trunkInterface, "classifier_egress")
	if err != nil {
		return err
	}

	err = setupLinkIFBFilter(ctx, ingressIFB, "classifier_ingress")
	if err != nil {
		return err
	}

	return nil
}

func setupIngressIFB(ctx context.Context) (netlink.Link, error) {
	_, numRXQueues, err := getQueueCount(ctx)
	if err != nil {
		return nil, err
	}
	link, err := netlink.LinkByName(vpc.IngressIFB)
	if err != nil && err.Error() == "Link not found" {
		logger.G(ctx).Info("Adding link: ", vpc.IngressIFB)
		ifb := netlink.Ifb{
			LinkAttrs: netlink.LinkAttrs{
				Name: vpc.IngressIFB,
				// Hardcoded
				TxQLen: 1000,
				// This is based on the number of Queues ENAs come with
				NumTxQueues: numRXQueues,
				NumRxQueues: numRXQueues,
				// AWS Upper bound of MTU
				MTU: 9001,
			},
		}
		if err2 := netlink.LinkAdd(&ifb); err2 != nil {
			return nil, err2
		}
		link, err = netlink.LinkByName(vpc.IngressIFB)
		if err != nil {
			return nil, errors.Wrap(err, "Cannot setup / add ifb")
		}
		return link, nil
	} else if err != nil {
		return nil, err
	}

	return link, nil
}

func getQueueCount(ctx context.Context) (int, int, error) {
	link, err := netlink.LinkByName("eth0")
	if err != nil {
		return 0, 0, errors.Wrap(err, "Cannot get link object for eth0, to retrieve queue count")
	}

	numTXQueues := link.Attrs().NumTxQueues
	numRXQueues := link.Attrs().NumTxQueues

	return numTXQueues, numRXQueues, nil
}

func addClsActToLink(ctx context.Context, link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Attrs().Parent == netlink.HANDLE_CLSACT && qdisc.Type() == "clsact" {
			return nil
		}
	}

	logger.G(ctx).Debugf("Setting up qdisc on: %+v", link)
	qdisc := clsAct{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    0xFFFF0000,
		},
	}
	return netlink.QdiscReplace(&qdisc)
}

type clsAct struct {
	netlink.QdiscAttrs
}

func (c *clsAct) Attrs() *netlink.QdiscAttrs {
	return &c.QdiscAttrs
}

func (c *clsAct) Type() string {
	return "clsact"
}

func setupHTBQdisc(ctx context.Context, link netlink.Link) error {
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

func setupIFBHTBRootClass(ctx context.Context, instanceType string, link netlink.Link) error {

	classattrs := netlink.ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.HANDLE_ROOT,
		Handle:    rootHtbClass,
	}

	rate := vpc.MustGetMaxNetworkbps(instanceType)
	htbclassattrs := netlink.HtbClassAttrs{
		Rate:    rate,
		Buffer:  9001,
		Cbuffer: 9001,
	}
	class := netlink.NewHtbClass(classattrs, htbclassattrs)
	return netlink.ClassReplace(class)
}

func setupLinkIFBFilter(ctx context.Context, link netlink.Link, filterName string) error {
	linkName := link.Attrs().Name
	filterData, err := filter.Asset("filter.o")
	if err != nil {
		return err
	}

	f, err := ioutil.TempFile("", "filter.o")
	if err != nil {
		return errors.Wrap(err, "Cannot make tempfile for filter.o")
	}
	defer f.Close()
	defer os.Remove(f.Name())

	_, err = f.Write(filterData)
	if err != nil {
		return errors.Wrap(err, "Cannot write filter data to tempfile")
	}
	err = f.Sync()
	if err != nil {
		return errors.Wrap(err, "Cannot sync tempfile")
	}
	f.Name()

	cmdWithContext := exec.CommandContext(ctx, "/sbin/tc", "filter", "replace", "dev", linkName, "protocol", "all", "parent",
		"1:0", "handle", "0x1", "pref", "32000", "bpf", "direct-action", "object-file", f.Name(), "section",
		filterName, "classid", "1:1")
	err = cmdWithContext.Run()
	if err != nil {
		return errors.Wrap(err, "Cannot run command to install filter")
	}
	return nil
}

/*
const (
	mtu = 9001
)



func configureQdiscs(ctx context.Context, networkInterfaces []*vpcapi.NetworkInterface, instanceType string) error {
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

	networkInterfacesMacMap := make(map[string]*vpcapi.NetworkInterface, len(networkInterfaces))
	for idx := range networkInterfaces {
		networkInterface := networkInterfaces[idx]
		networkInterfacesMacMap[networkInterface.MacAddress] = networkInterface
	}

	for _, link := range links {
		if networkInterface, ok := networkInterfacesMacMap[link.Attrs().HardwareAddr.String()]; !ok {
			logger.G(ctx).Debug("Skipping work on link, as it's not an ENI: ", link)
			continue
		} else if networkInterface.NetworkInterfaceAttachment.DeviceIndex == 0 {
			logger.G(ctx).Debug("Skipping work on link, as it's the default / root device")
			continue
		}
		logger.G(ctx).Debugf("Configuring link: %+v", link)
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

func configureFiltersForLink(ctx context.Context, link, ifbIngress, ifbEgress netlink.Link) error {
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

func configureQdiscsForLink(ctx context.Context, link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Attrs().Parent == netlink.HANDLE_CLSACT && qdisc.Type() == "clsact" {
			return nil
		}
	}

	logger.G(ctx).Debugf("Setting up qdisc on: %+v", link)
	qdisc := clsAct{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    0xFFFF0000,
		},
	}
	return netlink.QdiscReplace(&qdisc)
}

func getQueueCount(ctx context.Context) (int, int, error) {
	link, err := netlink.LinkByName("eth0")
	if err != nil {
		return 0, 0, errors.Wrap(err, "Cannot get link object for eth0, to retrieve queue count")
	}

	numTXQueues := link.Attrs().NumTxQueues
	numRXQueues := link.Attrs().NumTxQueues

	return numTXQueues, numRXQueues, nil
}

func setupIFBs(ctx context.Context, instanceType string) error {
	numTXQueues, numRXQueues, err := getQueueCount(ctx)
	if err != nil {
		return err
	}
	err = setupIFB(ctx, instanceType, vpc.IngressIFB, "classifier_ingress", unix.ETH_P_IP, numRXQueues)
	if err != nil {
		return err
	}

	return setupIFB(ctx, instanceType, vpc.EgressIFB, "classifier_egress", unix.ETH_P_ALL, numTXQueues)
}

func setupIFB(ctx context.Context, instanceType, ifbName, filterName string, filterProtocol uint16, queues int) error {
	link, err := netlink.LinkByName(ifbName)
	if err != nil && err.Error() == "Link not found" {
		logger.G(ctx).Info("Adding link: ", ifbName)
		ifb := netlink.Ifb{
			LinkAttrs: netlink.LinkAttrs{
				Name: ifbName,
				// Hardcoded
				TxQLen: 1000,
				// This is based on the number of Queues ENAs come with
				NumTxQueues: queues,
				NumRxQueues: queues,
				// AWS Upper bound of MTU
				MTU: 9001,
			},
		}
		if err2 := netlink.LinkAdd(&ifb); err2 != nil {
			return err2
		}
		// Retry
		return setupIFB(ctx, instanceType, ifbName, filterName, filterProtocol, queues)
	} else if err != nil {
		return err
	}
	// This is idempotent
	err = netlink.LinkSetUp(link)
	if err != nil {
		return err
	}

	err = setupIFBQdisc(ctx, instanceType, link)
	if err != nil {
		return err
	}

	return setupIFBBPFFilter(ctx, link, filterName, filterProtocol)
}

func setupIFBBPFFilter(ctx context.Context, link netlink.Link, filterName string, filterProtocol uint16) error {
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
			logger.G(ctx).WithError(e).Warning("Cannot close bpf program")
		}
	}()
	filterattrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.MakeHandle(1, 0),
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  filterProtocol,
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

func setupIFBQdisc(ctx context.Context, instanceType string, link netlink.Link) error {
	err := setupIFBHTBQdisc(ctx, link)
	if err != nil {
		return err
	}
	return setupIFBHTBRootClass(ctx, instanceType, link)
}
func setupIFBHTBRootClass(ctx context.Context, instanceType string, link netlink.Link) error {

	classattrs := netlink.ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.HANDLE_ROOT,
		Handle:    rootHtbClass,
	}

	rate := vpc.MustGetMaxNetworkbps(instanceType)
	htbclassattrs := netlink.HtbClassAttrs{
		Rate:    rate,
		Buffer:  uint32(float64(rate/8)/netlink.Hz() + float64(mtu)),
		Cbuffer: uint32(float64(rate/8)/netlink.Hz() + float64(mtu)),
	}
	class := netlink.NewHtbClass(classattrs, htbclassattrs)
	return netlink.ClassReplace(class)
}

func setupIFBHTBQdisc(ctx context.Context, link netlink.Link) error {
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
*/

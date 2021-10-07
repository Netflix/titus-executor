//go:build linux
// +build linux

package setup2

import (
	"context"
	"io/ioutil"
	"math"
	"os"
	"os/exec"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/bpf2/filter"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	rootHtbClass = netlink.MakeHandle(1, 1)
)

func configureQdiscs(ctx context.Context, trunkNetworkInterface *vpcapi.NetworkInterface, instanceType string) error {
	ingressIFB, err := setupIngressIFB(ctx)
	if err != nil {
		return err
	}
	trunkInterface, err := GetLinkByMac(trunkNetworkInterface.MacAddress)
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
	bytespersecond := math.Ceil(float64(rate) / 8.0)
	htbclassattrs := netlink.HtbClassAttrs{
		Rate:    rate,
		Buffer:  uint32(bytespersecond/netlink.Hz() + float64(link.Attrs().MTU) + 1),
		Cbuffer: uint32(bytespersecond/netlink.Hz() + 10*float64(link.Attrs().MTU) + 1),
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

var ErrLinkNotFound = errors.New("Link not found")

func GetLinkByMac(mac string) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		if link.Attrs().HardwareAddr.String() == mac {
			return link, nil
		}
	}

	return nil, ErrLinkNotFound
}

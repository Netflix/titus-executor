// +build linux

package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/sirupsen/logrus"
	"github.com/wercker/journalhook"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/Netflix/titus-executor/utils"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
)

const (
	contName = "imdsproxy"
	peerName = "container"
)

func init() {
	// namespaces are per task
	runtime.LockOSThread()

	// use journald for logs
	journalhook.Enable()
}

func getPeerNsPath(podName string) string {
	return fmt.Sprintf("/var/run/netns/imds-%s", podName)
}

func mountNs(ns netns.NsHandle, peerNsPath string) error {
	err := netns.Set(ns)
	if err != nil {
		return errors.Wrap(err, "netns.Set")
	}

	mount, err := os.Create(peerNsPath)
	if err != nil {
		return errors.Wrap(err, "os.Create")
	}
	_ = mount.Close()

	err = unix.Mount(utils.CurrThreadNetNs, peerNsPath, "none", unix.MS_BIND, "")
	if err != nil {
		return errors.Wrap(err, "unix.Mount")
	}

	return nil
}

func getContainerIP(prevResult *current.Result) (net.IP, error) {
	for idx, iface := range prevResult.Interfaces {
		if iface.Name == "eth0" {
			return prevResult.IPs[idx].Address.IP, nil
		}
	}
	return nil, errors.New("could not find default interface")
}

func cmdAdd(args *skel.CmdArgs) error {
	logrus.Debugf("add %#v", args)

	prevResult, err := getPrev(args)
	if err != nil {
		logrus.Errorf("getPrev %s", err)
		return err
	}
	logrus.Debugf("getPrev %#v", prevResult)

	containerIP, err := getContainerIP(prevResult)
	if err != nil {
		logrus.Errorf("getContainerIP %s", err)
		return err
	}

	pod, err := getPod(args)
	if err != nil {
		logrus.Errorf("getPod %s", err)
		return err
	}
	logrus.Debugf("getPod %#v", pod)

	env, err := extractEnv(prevResult, pod)
	if err != nil {
		logrus.Errorf("extractEnv %s", err)
		return err
	}
	logrus.Debugf("extractEnv %#v", env)

	// create new namespaces

	peerNs, err := netns.New()
	if err != nil {
		logrus.Errorf("peerNs %s", err)
		return err

	}
	logrus.Debugf("peerNs %#v", peerNs)

	contNs, err := netns.GetFromPath(args.Netns)
	if err != nil {
		logrus.Errorf("contNs %s", err)
		return err
	}
	logrus.Debugf("contNs %#v", contNs)

	// create veth from container ns

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:      contName,
			Namespace: netlink.NsFd(contNs),
			Flags:     net.FlagUp,
		},
		PeerName: peerName,
	}
	logrus.Debugf("veth %#v", veth)

	if err := netlink.LinkAdd(veth); err != nil {
		logrus.Errorf("LinkAdd %s", err)
		return err
	}
	logrus.Debugf("LinkAdd %#v", veth)

	// forward declare for gotos

	var peerLink, contLink netlink.Link
	var route *netlink.Route

	var peerNsPath string
	var errA error

	// move the peer veth into the peer namespace, link up

	peerLink, err = netlink.LinkByName(peerName)
	if err != nil {
		logrus.Errorf("LinkByName(%s) %s", peerName, err)
		goto failLink
	}
	logrus.Debugf("peerLink %#v", peerLink)

	err = netlink.AddrAdd(peerLink, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP("169.254.169.254"),
			Mask: net.CIDRMask(32, 32),
		},
	})
	if err != nil {
		logrus.Errorf("AddrAdd %s", err)
		goto failLink
	}
	logrus.Debugf("AddrAdd succeeded")

	err = netlink.LinkSetNsFd(peerLink, int(peerNs))
	if err != nil {
		logrus.Errorf("LinkSetNsFd %s", err)
		goto failLink
	}

	err = netns.Set(peerNs)
	if err != nil {
		logrus.Errorf("setNs %s", err)
		goto failLink
	}

	// set peer link up, add default route

	err = netlink.LinkSetUp(peerLink)
	if err != nil {
		logrus.Errorf("LinkSetUp %s", err)
		goto failLink
	}

	route = &netlink.Route{
		LinkIndex: peerLink.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.ParseIP("0.0.0.0"),
			Mask: net.CIDRMask(0, 32),
		},
		Priority: unix.RTA_GATEWAY,
	}
	logrus.Infof("route %#v", route)

	err = netlink.RouteAdd(route)
	if err != nil {
		logrus.Errorf("RouteAdd %s", err)
		goto failLink
	}
	logrus.Debugf("peer route %#v", route)

	// setup routing inside the container namespace

	err = netns.Set(contNs)
	if err != nil {
		logrus.Errorf("setNs %s", err)
		goto failLink
	}

	contLink, err = netlink.LinkByName(contName)
	if err != nil {
		logrus.Errorf("LinkByName(%s) %s", contName, err)
		goto failLink
	}
	logrus.Debugf("contLink %#v", contLink)

	route = &netlink.Route{
		LinkIndex: contLink.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.ParseIP("169.254.169.254"),
			Mask: net.CIDRMask(32, 32),
		},
		Priority: unix.RTA_GATEWAY,
		Scope:    netlink.SCOPE_LINK,
		Protocol: syscall.RTPROT_STATIC,
		Src:      containerIP,
	}
	logrus.Debugf("cont route %#v", route)

	err = netlink.RouteAdd(route)
	if err != nil {
		logrus.Errorf("RouteAdd %s", err)
		goto failLink
	}
	logrus.Debugf("RouteAdd %#v", route)

	// mount the peer routing namespace for the proxy to use

	peerNsPath = getPeerNsPath(pod.Name)

	err = mountNs(peerNs, peerNsPath)
	if err != nil {
		logrus.Errorf("mountNs %s", err)
		goto failMount
	}

	// start systemd unit for the imds proxy

	err = setupEnv(pod, env)
	if err != nil {
		logrus.Errorf("setupEnv %s", err)
		goto failMount
	}

	err = writeNetworkNamespaceFile(pod, args.Netns)
	if err != nil {
		logrus.Errorf("writeNetworkNamespaceFile %s", err)
		goto failMount
	}

	err = startUnit(pod.Name)
	if err != nil {
		logrus.Errorf("startUnit %s", err)
		goto failUnit
	}

	prevResult.Interfaces = append(prevResult.Interfaces, &current.Interface{
		Name:    contLink.Attrs().Name,
		Mac:     contLink.Attrs().HardwareAddr.String(),
		Sandbox: args.Netns,
	})
	prevResult.Interfaces = append(prevResult.Interfaces, &current.Interface{
		Name:    peerLink.Attrs().Name,
		Mac:     peerLink.Attrs().HardwareAddr.String(),
		Sandbox: peerNsPath,
	})
	logrus.Infof("result %s", prevResult)

	return types.PrintResult(prevResult, version.Current())

failUnit:
	errA = stopUnit(pod.Name)
	if errA != nil {
		logrus.Errorf("stopUnit %s", errA)
	}
	logrus.Debug("stopUnit succeeded")

failMount:
	unmountNs(peerNsPath)
	// this namespace will cease to exist when cni exits

failLink:
	errA = netns.Set(peerNs)
	if errA != nil {
		logrus.Errorf("setNs %s", errA)
	}

	errA = netlink.LinkDel(peerLink)
	if errA != nil {
		logrus.Errorf("LinkDel %s", errA)
	}

	return err
}

func cmdCheck(args *skel.CmdArgs) error {
	logrus.Debugf("check %#v", args)

	return checkUnit(args.ContainerID)
}

func unmountNs(peerNsPath string) {
	logrus.Infof("peerNsPath %s", peerNsPath)

	err := unix.Unmount(peerNsPath, 0)
	if err != nil {
		logrus.Errorf("unix.Unmount %s", err)
	}
	logrus.Debugf("unix.Unmount suceeded")

	err = os.RemoveAll(peerNsPath)
	if err != nil {
		logrus.Errorf("os.RemoveAll %s", err)
	}
	logrus.Debugf("os.RemoveAll succeeded")
}

func cmdDel(args *skel.CmdArgs) error {
	logrus.Debugf("del %#v", args)

	podName, err := getPodName(args)
	if err != nil {
		logrus.Errorf("getPodName %s", err)
		return err
	}
	logrus.Debugf("getPodName %s", podName)

	// stop systemd unit for proxy

	err = stopUnit(podName)
	if err != nil {
		logrus.Errorf("stopUnit %s", err)
		return err
	}

	// save current namespace

	origNs, err := netns.Get()
	if err != nil {
		logrus.Errorf("origNs %s", err)
		return err
	}
	logrus.Debugf("origNs %#v", origNs)

	// switch to peer namespace and remove veth

	peerNsPath := getPeerNsPath(podName)

	fi, err := os.Stat(peerNsPath)
	if err != nil {
		logrus.Errorf("Cannot find peer namespace %s", err)
		return err
	}
	logrus.Debugf("peerNs %s %#v", peerNsPath, fi)

	stat := syscall.Statfs_t{}
	err = syscall.Statfs(peerNsPath, &stat)
	if err != nil {
		logrus.Errorf("Statfs %s", err)
		return err
	}
	logrus.Debugf("Statfs %#v", stat)

	if stat.Type != unix.NSFS_MAGIC {
		return fmt.Errorf("%s is not namespace", peerNsPath)
	}

	peerNs, err := netns.GetFromPath(peerNsPath)
	if err != nil {
		logrus.Errorf("peerNs %s", err)
		return err
	}
	logrus.Debugf("peerNs %#v", peerNs)

	err = netns.Set(peerNs)
	if err != nil {
		logrus.Errorf("setNs %s", err)
		return err
	}

	peerLink, err := netlink.LinkByName(peerName)
	if err != nil {
		logrus.Errorf("LinkByName %s", err)
		return err
	}
	logrus.Debugf("LinkByName %#v", peerLink)

	err = netlink.LinkDel(peerLink)
	if err != nil {
		logrus.Errorf("LinkDel %s", err)
		return err
	}
	logrus.Debugf("LinkDel %#v", peerLink)

	// switch to orig namespace, unmount peer namespace

	err = netns.Set(origNs)
	if err != nil {
		logrus.Errorf("setNs %s", err)
		return err
	}
	logrus.Debugf("setNs %#v", origNs)

	err = peerNs.Close()
	if err != nil {
		logrus.Errorf("closeNs %s", err)
		return err
	}
	unmountNs(peerNsPath)

	return nil
}

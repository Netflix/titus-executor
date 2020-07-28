package main

import (
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
)

var VersionInfo = version.PluginSupports("0.3.0", "0.3.1")

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, VersionInfo, "IMDS CNI")
}

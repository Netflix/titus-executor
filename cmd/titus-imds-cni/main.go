package main

import (
	"github.com/Netflix/titus-executor/metadataserver/cni"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
)

var VersionInfo = version.PluginSupports("0.3.0", "0.3.1")

func main() {
	skel.PluginMain(cni.Command.Add, cni.Command.Chk, cni.Command.Del, VersionInfo, "IMDS proxy CNI")
}

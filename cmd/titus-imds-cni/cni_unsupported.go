// +build !linux

package main

import (
	"github.com/Netflix/titus-executor/utils"
	"github.com/containernetworking/cni/pkg/skel"
)

func cmdAdd(args *skel.CmdArgs) error {
	return utils.ErrorUnsupportedPlatform
}

func cmdCheck(args *skel.CmdArgs) error {
	return utils.ErrorUnsupportedPlatform
}

func cmdDel(args *skel.CmdArgs) error {
	return utils.ErrorUnsupportedPlatform
}

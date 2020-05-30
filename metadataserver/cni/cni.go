package cni

import "github.com/containernetworking/cni/pkg/skel"

type ImdsCni struct {
	Add func(_ *skel.CmdArgs) error
	Del func(_ *skel.CmdArgs) error
	Chk func(_ *skel.CmdArgs) error
}

var Command = &ImdsCni{
	Add: cmdAdd,
	Del: cmdDel,
	Chk: cmdCheck,
}

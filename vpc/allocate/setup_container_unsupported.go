// +build !linux

package allocate

import (
	"github.com/Netflix/titus-executor/vpc/context"
	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/vishvananda/netlink"
)

func doSetupContainer(parentCtx context.VPCContext, netnsfd, bandwidth int, burst bool, allocation types.Allocation) (netlink.Link, error) {
	return nil, types.ErrUnsupported
}

func teardownNetwork(ctx context.VPCContext, allocation types.Allocation, link netlink.Link, netnsfd int) {
}

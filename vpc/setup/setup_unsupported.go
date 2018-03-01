// +build !linux

package setup

import "github.com/Netflix/titus-executor/vpc/types"
import "github.com/Netflix/titus-executor/vpc/context"

func configureQdiscs(ctx context.VPCContext) error {
	return types.ErrUnsupported
}

func setupIFBs(ctx context.VPCContext) error {
	return types.ErrUnsupported
}

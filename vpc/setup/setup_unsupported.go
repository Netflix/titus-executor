// +build !linux

package setup

import (
	"context"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/types"
)

func configureQdiscs(ctx context.Context, networkInterfaces []*vpcapi.NetworkInterface, instanceType string) error {
	return types.ErrUnsupported
}

func setupIFBs(ctx context.Context, instanceType string) error {
	return types.ErrUnsupported
}

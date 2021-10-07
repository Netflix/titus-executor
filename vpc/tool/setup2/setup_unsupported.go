//go:build !linux
// +build !linux

package setup2

import (
	"context"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/types"
)

func configureQdiscs(ctx context.Context, trunkNetworkInterface *vpcapi.NetworkInterface, instanceType string) error {
	return types.ErrUnsupported
}

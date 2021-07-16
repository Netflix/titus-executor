// +build !linux

package containerccas

import (
	"context"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/types"
)

func DoSetupContainer(ctx context.Context, netnsfd int, allocation *vpcapi.CCAS) error {
	return types.ErrUnsupported
}

func DoTeardownContainer(ctx context.Context, allocation *vpcapi.CCAS, netnsfd int) error {
	return types.ErrUnsupported
}

func TeardownNetwork(ctx context.Context, allocation *vpcapi.CCAS) error {
	return types.ErrUnsupported
}

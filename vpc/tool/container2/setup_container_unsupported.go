// +build !linux

package container2

import (
	"context"

	"github.com/Netflix/titus-executor/vpc/types"
)

func DoSetupContainer(ctx context.Context, netnsfd int, bandwidth, ceil uint64, jumbo bool, allocation types.Allocation) error {
	return types.ErrUnsupported
}

func DoTeardownContainer(ctx context.Context, allocation types.Allocation, netnsfd int) error {
	return types.ErrUnsupported
}

func TeardownNetwork(ctx context.Context, allocation types.Allocation) error {
	return types.ErrUnsupported
}

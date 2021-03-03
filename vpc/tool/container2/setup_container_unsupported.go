// +build !linux

package container2

import (
	"context"

	"github.com/Netflix/titus-executor/vpc/types"
)

func DoSetupContainer(ctx context.Context, netns []interface{}, withTrans bool, bandwidth, ceil uint64, allocation types.Allocation) error {
	return types.ErrUnsupported
}

func DoTeardownContainer(ctx context.Context, allocation types.Allocation, netns []interface{}) error {
	return types.ErrUnsupported
}

func TeardownNetwork(ctx context.Context, allocation types.Allocation) error {
	return types.ErrUnsupported
}

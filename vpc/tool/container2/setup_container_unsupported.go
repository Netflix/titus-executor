//go:build !linux
// +build !linux

package container2

import (
	"context"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/types"
)

func DoSetupContainer(ctx context.Context, pid1dirfd int, transitionNamespaceDir string, intassignment *vpcapi.AssignIPResponseV3) error {
	return types.ErrUnsupported
}

func DoTeardownContainer(ctx context.Context, allocation *vpcapi.AssignIPResponseV3, netnsfd int) error {
	return types.ErrUnsupported
}

func TeardownNetwork(ctx context.Context, allocation *vpcapi.AssignIPResponseV3) error {
	return types.ErrUnsupported
}

// +build !linux

package setup2

import (
	"context"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/types"
)

func configureQdiscs(ctx context.Context, provisionInstanceResponse *vpcapi.ProvisionInstanceResponseV2, instanceType string) error {
	return types.ErrUnsupported
}

/*
import (
	"context"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/types"
)


func setupIFBs(ctx context.Context, instanceType string) error {
	return types.ErrUnsupported
}
*/

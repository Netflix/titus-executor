// +build !linux

package setup2

import (
	"context"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"

	"github.com/Netflix/titus-executor/vpc/types"
)

func configureQdiscs(ctx context.Context, provisionInstanceResponse *vpcapi.ProvisionInstanceResponseV3) error {
	return types.ErrUnsupported
}

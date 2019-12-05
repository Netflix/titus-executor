package genconf

import (
	"context"
	"fmt"

	"github.com/Netflix/titus-executor/vpc/limits"

	"github.com/Netflix/titus-executor/vpc/tool/identity"
)

func GenConf(ctx context.Context, identityProvider identity.InstanceIdentityProvider, export, resourceSetsOnly bool) error {
	instanceIdentity, err := identityProvider.GetIdentity(ctx)
	if err != nil {
		return err
	}

	maxInterfaces := limits.MustGetMaxInterfaces(instanceIdentity.InstanceType)
	maxIPs := limits.MustGetMaxIPAddresses(instanceIdentity.InstanceType)
	maxNetworkMbps := limits.MustGetMaxNetworkMbps(instanceIdentity.InstanceType)
	// The number of interfaces exposed to the Titus scheduler is the maximum number of interfaces this instance can handle minus 1.
	resourceSet := fmt.Sprintf("ResourceSet-ENIs-%d-%d", maxInterfaces-1, maxIPs)
	if resourceSetsOnly {
		fmt.Println(resourceSet)
		return nil
	}
	prelude := ""
	if export {
		prelude = "export "
	}
	fmt.Println(prelude + fmt.Sprintf(`eni_res="%s"`, resourceSet))
	fmt.Println(prelude + fmt.Sprintf(`TITUS_NETWORK_BANDWIDTH_MBS="%d"`, maxNetworkMbps))
	return nil
}

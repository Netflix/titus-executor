package genconf

import (
	"context"
	"fmt"

	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
)

func GenConf(ctx context.Context, identityProvider identity.InstanceIdentityProvider, export, resourceSetsOnly bool, generation string) error {
	instanceIdentity, err := identityProvider.GetIdentity(ctx)
	if err != nil {
		return err
	}

	var resourceSet string
	maxIPs := vpc.MustGetMaxIPAddresses(instanceIdentity.InstanceType)
	maxNetworkMbps := vpc.MustGetMaxNetworkMbps(instanceIdentity.InstanceType)

	switch generation {
	case "v3":
		maxBranchENIs := vpc.MustGetMaxBranchENIs(instanceIdentity.InstanceType)
		resourceSet = fmt.Sprintf("ResourceSet-ENIs-%d-%d", maxBranchENIs, maxIPs)
	default:
		return fmt.Errorf("Unknown generation %q", generation)
	}
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

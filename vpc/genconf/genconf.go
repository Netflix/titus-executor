package genconf

import (
	"github.com/Netflix/titus-executor/vpc/context"
	"gopkg.in/urfave/cli.v1"

	"fmt"

	"github.com/Netflix/titus-executor/vpc"
)

var export bool
var resourceSetOnly bool

var GenConf = cli.Command{ // nolint: golint
	Name:   "genconf",
	Usage:  "Generate Mesos Agent Configuration",
	Action: context.WrapFunc(genConf),
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:        "export",
			Usage:       "Generate environment variables with export declaration",
			Destination: &export,
		},
		cli.BoolFlag{
			Name:        "resource-sets-only",
			Usage:       "Don't generate environment variables, just the resourceset declaration",
			Destination: &resourceSetOnly,
		},
	},
}

func genConf(parentCtx *context.VPCContext) error {

	if err := doGenConf(parentCtx); err != nil {
		return cli.NewMultiError(cli.NewExitError("Unable to generate config", 1), err)
	}

	return nil
}

func doGenConf(parentCtx *context.VPCContext) error {
	maxInterfaces := vpc.GetMaxInterfaces(parentCtx.InstanceType)
	maxIPs := vpc.GetMaxIPAddresses(parentCtx.InstanceType)
	maxNetworkMbps := vpc.GetMaxNetworkMbps(parentCtx.InstanceType)
	// The number of interfaces exposed to the Titus scheduler is the maximum number of interfaces this instance can handle minus 1.
	resourceSet := fmt.Sprintf("ResourceSet-ENIs-%d-%d", maxInterfaces-1, maxIPs)
	if resourceSetOnly {
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

package gc

import (
	"time"

	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/allocate"
	"github.com/Netflix/titus-executor/vpc/context"
	"github.com/Netflix/titus-executor/vpc/ec2wrapper"
	"gopkg.in/urfave/cli.v1"
)

var GC = cli.Command{ // nolint: golint
	Name:   "gc",
	Usage:  "Garbage collect unused IP addresses",
	Action: context.WrapFunc(gc),
	Flags: []cli.Flag{
		cli.DurationFlag{
			Name:  "grace-period",
			Usage: "How long does the IP have be unused before we trigger GC, must be greater than or equal to the refresh interval",
			Value: vpc.RefreshInterval * 2,
		},
		cli.DurationFlag{
			Name:  "timeout",
			Usage: "Maximum amount of time allowed running GC",
			Value: time.Minute * 5,
		},
	},
}

func gc(parentCtx context.VPCContextWithCLI) error {
	gracePeriod := parentCtx.CLIContext().Duration("grace-period")
	if gracePeriod < vpc.RefreshInterval {
		return cli.NewExitError("Refresh interval invalid", 1)
	}

	timeout := parentCtx.CLIContext().Duration("timeout")
	ctx, cancel := parentCtx.WithTimeout(timeout)
	defer cancel()

	parentCtx.Logger().WithField("grace-period", gracePeriod).Debug()
	if err := doGc(ctx, gracePeriod); err != nil {
		return cli.NewMultiError(cli.NewExitError("Unable to run GC", 1), err)
	}

	return nil
}

func doGc(parentCtx context.VPCContext, gracePeriod time.Duration) error {
	interfaces, err := parentCtx.EC2metadataClientWrapper().Interfaces()
	if err != nil {
		return err
	}

	for _, networkInterface := range interfaces {

		ctx := parentCtx.WithField("interface", networkInterface.InterfaceID)
		err = doGcInterface(ctx, gracePeriod, &networkInterface)
		if err != nil {
			return err
		}
	}
	return nil
}

func doGcInterface(parentCtx context.VPCContext, gracePeriod time.Duration, networkInterface *ec2wrapper.EC2NetworkInterface) error {
	// Don't run GC on the primary interface
	if networkInterface.DeviceNumber == 0 {
		parentCtx.Logger().Debug("Not running GC on this interface")
		return nil
	}

	err := allocate.NewIPPoolManager(networkInterface).DoGc(parentCtx, gracePeriod)
	if err != nil {
		return cli.NewMultiError(cli.NewExitError("Unable to GC interfaces", 1), err)
	}
	return nil
}

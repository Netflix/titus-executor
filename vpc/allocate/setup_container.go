package allocate

import (
	"encoding/json"
	"os"
	"os/signal"

	"github.com/Netflix/titus-executor/vpc/context"
	"github.com/Netflix/titus-executor/vpc/types"
	"golang.org/x/sys/unix"
	"gopkg.in/urfave/cli.v1"
)

var SetupContainer = cli.Command{ // nolint: golint
	Name:   "setup-container",
	Usage:  "Setup networking for a particular container",
	Action: context.WrapFunc(setupContainer),
	Flags: []cli.Flag{
		cli.IntFlag{
			Name:  "netns",
			Usage: "The File Descriptor # of the network namespace to setup",
		},
		cli.Uint64Flag{
			Name:  "bandwidth",
			Usage: "Bandwidth to allocate to the device, in bps",
			Value: 128 * 1024 * 1024,
		},
		cli.BoolFlag{
			Name:  "burst",
			Usage: "Allow this container to burst its network allocation",
		},
	},
}

func setupContainer(parentCtx *context.VPCContext) error {
	burst := parentCtx.CLIContext.Bool("burst")
	bandwidth := parentCtx.CLIContext.Uint64("bandwidth")
	netns := parentCtx.CLIContext.Int("netns")
	if netns <= 0 {
		return cli.NewExitError("netns required", 1)
	}

	var allocation types.Allocation
	err := json.NewDecoder(os.Stdin).Decode(&allocation)
	if err != nil {
		return cli.NewMultiError(cli.NewExitError("Unable to read allocation", 1), err)
	}

	link, err := doSetupContainer(parentCtx, netns, bandwidth, burst, allocation)
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(types.WiringStatus{Success: false, Error: err.Error()})
		return cli.NewMultiError(cli.NewExitError("Unable to setup container", 1), err)
	}

	err = json.NewEncoder(os.Stdout).Encode(types.WiringStatus{Success: true, Error: ""})
	if err != nil {
		parentCtx.Logger.Error("Unable to write wiring status: ", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, unix.SIGTERM, unix.SIGINT)
	<-c

	parentCtx.Logger.Info("Beginning shutdown, and container teardown: ", allocation)
	teardownNetwork(parentCtx, allocation, link, netns)
	// TODO: Teardown turned up network namespace
	parentCtx.Logger.Info("Finished shutting down and deallocating")
	return nil
}

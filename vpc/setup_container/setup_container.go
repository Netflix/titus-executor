package setup_container

import (
	"encoding/json"
	"os"
	"os/signal"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/identity"
	"github.com/pkg/errors"

	"context"

	"github.com/Netflix/titus-executor/vpc/types"
	"golang.org/x/sys/unix"
)

func SetupContainer(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, netns int, bandwidth uint64, burst, jumbo bool) error {
	var allocation types.Allocation
	err := json.NewDecoder(os.Stdin).Decode(&allocation)
	if err != nil {
		return errors.Wrap(err, "Unable to read allocation")
	}

	ceil := bandwidth
	if burst {
		instanceIdentity, err := instanceIdentityProvider.GetIdentity()
		if err != nil {
			return errors.Wrap(err, "Cannot get instance identity")
		}
		ceil = vpc.GetMaxNetworkbps(instanceIdentity.InstanceType)
	}
	link, err := doSetupContainer(ctx, netns, bandwidth, ceil, jumbo, allocation)
	if err != nil {
		// warning: Errors unhandled.,LOW,HIGH (gosec)
		_ = json.NewEncoder(os.Stdout).Encode(types.WiringStatus{Success: false, Error: err.Error()}) // nolint: gosec
		return errors.Wrap(err, "Unable to setup container")
	}

	err = json.NewEncoder(os.Stdout).Encode(types.WiringStatus{Success: true, Error: ""})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to write wiring status")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, unix.SIGTERM, unix.SIGINT)
	<-c

	logger.G(ctx).WithField("allocation", allocation).Logger.Info("Beginning shutdown, and container teardown")
	teardownNetwork(ctx, allocation, link, netns)
	// TODO: Teardown turned up network namespace
	logger.G(ctx).Info("Finished shutting down and deallocating")
	return nil
}

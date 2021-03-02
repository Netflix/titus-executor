package container // nolint:dupl

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func SetupContainer(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, netns interface{}, bandwidth uint64, burst, jumbo bool) error {
	var allocation types.LegacyAllocation
	err := json.NewDecoder(os.Stdin).Decode(&allocation)
	if err != nil {
		return errors.Wrap(err, "Unable to read allocation")
	}

	ceil := bandwidth
	if burst {
		instanceIdentity, err := instanceIdentityProvider.GetIdentity(ctx)
		if err != nil {
			return errors.Wrap(err, "Cannot get instance identity")
		}
		ceil, err = vpc.GetMaxNetworkbps(instanceIdentity.InstanceType)
		if err != nil {
			return errors.Wrap(err, "Cannot get max network bps, and burst is set")
		}
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

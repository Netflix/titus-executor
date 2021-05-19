package container2 // nolint:dupl

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/golang/protobuf/jsonpb"
	"github.com/pkg/errors"
)

func SetupContainer(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, netns int, bandwidth uint64, burst bool) error {
	var assignment vpcapi.Assignment
	err := jsonpb.Unmarshal(os.Stdin, &assignment)
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

	switch t := assignment.Assignment.(type) {
	case *vpcapi.Assignment_AssignIPResponseV3:
		err = DoSetupContainer(ctx, netns, bandwidth, ceil, t.AssignIPResponseV3)
		if err != nil {
			// warning: Errors unhandled.,LOW,HIGH (gosec)
			_ = json.NewEncoder(os.Stdout).Encode(types.WiringStatus{Success: false, Error: err.Error()}) // nolint: gosec
			return errors.Wrap(err, "Unable to setup container")
		}
	default:
		return fmt.Errorf("Unknown assignment type received: %t", t)
	}

	err = json.NewEncoder(os.Stdout).Encode(types.WiringStatus{Success: true, Error: ""})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to write wiring status")
	}
	return nil
}

func TeardownContainer(ctx context.Context, netnsfd int) error {
	var assignment vpcapi.Assignment
	err := jsonpb.Unmarshal(os.Stdin, &assignment)
	if err != nil {
		return errors.Wrap(err, "Unable to read allocation")
	}

	switch t := assignment.Assignment.(type) {
	case *vpcapi.Assignment_AssignIPResponseV3:
		return DoTeardownContainer(ctx, t.AssignIPResponseV3, netnsfd)
	default:
		return fmt.Errorf("Unknown assignment type received: %t", t)
	}

}

package container2 // nolint:dupl

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/Netflix/titus-executor/vpc/types"

	// google.golang.org/protobuf/encoding/protojson doesn't yet implement streaming deserialization
	"github.com/golang/protobuf/jsonpb" // nolint: staticcheck
	"github.com/pkg/errors"
)

func SetupContainer(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, pid1dirfd int, transitionNamespaceDir string) error {
	var assignment vpcapi.Assignment
	err := jsonpb.Unmarshal(os.Stdin, &assignment)
	if err != nil {
		return errors.Wrap(err, "Unable to read allocation")
	}

	switch t := assignment.Assignment.(type) {
	case *vpcapi.Assignment_AssignIPResponseV3:
		err = DoSetupContainer(ctx, pid1dirfd, transitionNamespaceDir, t.AssignIPResponseV3)
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

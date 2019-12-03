package setup2

import (
	"context"
	"net"
	"time"

	"github.com/pkg/errors"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/Netflix/titus-executor/vpc/utilities"
	"google.golang.org/grpc"
)

const (
	maxSetupTime = 2 * time.Minute
)

func Setup(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, conn *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(ctx, maxSetupTime)
	defer cancel()

	lockTimeout := time.Second

	exclusiveLock, err := locker.ExclusiveLock(ctx, utilities.GetGlobalConfigurationLock(), &lockTimeout)
	if err != nil {
		return err
	}
	defer exclusiveLock.Unlock()

	instanceIdentity, err := instanceIdentityProvider.GetIdentity(ctx)
	if err != nil {
		return err
	}
	client := vpcapi.NewTitusAgentVPCServiceClient(conn)

	provisionInstanceRequest := &vpcapi.ProvisionInstanceRequestV2{
		InstanceIdentity: instanceIdentity,
	}

	provisionInstanceResponse, err := client.ProvisionInstanceV2(ctx, provisionInstanceRequest)
	if err != nil {
		return err
	}

	err = waitForInterfaceUp(ctx, provisionInstanceResponse.TrunkNetworkInterface)
	if err != nil {
		return err
	}
	err = configureQdiscs(ctx, provisionInstanceResponse, instanceIdentity.InstanceType)
	if err != nil {
		return errors.Wrap(err, "Unable to setup QDiscs")
	}

	/*
		err = waitForInterfacesUp(ctx, provisionInstanceResponse.NetworkInterfaces)
		if err != nil {
			return err
		}



		// Setup qdiscs on ENI interfaces
		err = configureQdiscs(ctx, provisionInstanceResponse.NetworkInterfaces, instanceIdentity.InstanceType)
		if err != nil {
			return errors.Wrap(err, "Unable to setup qdiscs")
		}
	*/
	return nil
}

func waitForInterfaceUp(ctx context.Context, networkInterface *vpcapi.NetworkInterface) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
			if interfaceUp, err := interfaceUp(ctx, networkInterface); err != nil {
				return err
			} else if interfaceUp {
				return nil
			}
		}
	}
}

func interfaceUp(ctx context.Context, networkInterface *vpcapi.NetworkInterface) (bool, error) {
	logger.G(ctx).Info("Waiting for interfaces to come up")
	attachedInterfaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}

	for _, attachedInterface := range attachedInterfaces {
		if attachedInterface.HardwareAddr.String() != networkInterface.MacAddress {
			continue
		}
		if attachedInterface.Flags&net.FlagUp == 1 {
			logger.G(ctx).WithField("interface", networkInterface).Info("Interface up")
			return true, nil
		}
	}

	logger.G(ctx).WithField("interface", networkInterface).Info("Interface mac not found")
	return false, nil
}

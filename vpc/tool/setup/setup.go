package setup

import (
	"context"
	"net"
	"time"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/Netflix/titus-executor/vpc/utilities"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

const (
	maxSetupTime = 2 * time.Minute
)

func Setup(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, conn *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(ctx, maxSetupTime)
	defer cancel()

	lockTimeout := time.Second

	exclusiveLock, err := locker.ExclusiveLock(utilities.GetGlobalConfigurationLock(), &lockTimeout)
	if err != nil {
		return err
	}
	defer exclusiveLock.Unlock()

	instanceIdentity, err := instanceIdentityProvider.GetIdentity(ctx)
	if err != nil {
		return err
	}
	client := vpcapi.NewTitusAgentVPCServiceClient(conn)

	provisionInstanceRequest := &vpcapi.ProvisionInstanceRequest{
		InstanceIdentity: instanceIdentity,
	}
	provisionInstanceResponse, err := client.ProvisionInstance(ctx, provisionInstanceRequest)
	if err != nil {
		return err
	}

	err = waitForInterfacesUp(ctx, provisionInstanceResponse.NetworkInterfaces)
	if err != nil {
		return err
	}

	err = setupIFBs(ctx, instanceIdentity.InstanceType)
	if err != nil {
		return errors.Wrap(err, "Unable to setup IFBs")
	}

	// Setup qdiscs on ENI interfaces
	err = configureQdiscs(ctx, provisionInstanceResponse.NetworkInterfaces, instanceIdentity.InstanceType)
	if err != nil {
		return errors.Wrap(err, "Unable to setup qdiscs")
	}
	return nil
}

func waitForInterfacesUp(ctx context.Context, networkInterfaces []*vpcapi.NetworkInterface) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
			if interfacesUp, err := allInterfacesUp(ctx, networkInterfaces); err != nil {
				return err
			} else if interfacesUp {
				return nil
			}
		}
	}
}

func allInterfacesUp(ctx context.Context, networkInterfaces []*vpcapi.NetworkInterface) (bool, error) {
	logger.G(ctx).Info("Waiting for interfaces to come up")
	attachedInterfaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}

	attachedInterfaceMacMap := make(map[string]net.Interface, len(attachedInterfaces))
	for idx := range attachedInterfaces {
		attachedInterface := attachedInterfaces[idx]
		attachedInterfaceMacMap[attachedInterface.HardwareAddr.String()] = attachedInterface
	}

	for idx := range networkInterfaces {
		ni := networkInterfaces[idx]

		attachedInterface, ok := attachedInterfaceMacMap[ni.MacAddress]
		if !ok {
			logger.G(ctx).WithField("interface", ni).Info("Interface mac not found")
			return false, nil
		}
		if attachedInterface.Flags&net.FlagUp == 0 {
			logger.G(ctx).WithField("interface", ni).Info("Interface not up")
			return false, nil
		}
	}

	return true, nil
}

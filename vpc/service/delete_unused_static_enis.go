package service

import (
	"context"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
)

var staticENILastReconciled = map[string]time.Time{}

func (vpcService *vpcService) deleteUnusedStaticENILoop(ctx context.Context, protoItem keyedItem) error {

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	item := protoItem.(*subnet)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"subnet":    item.subnetID,
		"accountID": item.accountID,
		"az":        item.az,
	})

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		AccountID: item.accountID,
		Region:    item.region,
	})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not get session")
		return err
	}

	describeNetworkInterfacesInput := ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("description"),
				Values: aws.StringSlice([]string{staticDummyInterfaceDescription}),
			},
			{
				Name:   aws.String("owner-id"),
				Values: aws.StringSlice([]string{item.accountID}),
			},
		},
		MaxResults: aws.Int64(1000),
	}

	networkInterfaces := []*ec2.NetworkInterface{}
	for {
		describeNetworkInterfacesOutput, err := session.DescribeNetworkInterfaces(ctx, describeNetworkInterfacesInput)
		if err != nil {
			err = errors.Wrap(err, "Cannot describe network interfaces")
			return err
		}

		networkInterfaces = append(networkInterfaces, describeNetworkInterfacesOutput.NetworkInterfaces...)

		if describeNetworkInterfacesOutput.NextToken == nil {
			break
		}
		describeNetworkInterfacesInput.NextToken = describeNetworkInterfacesOutput.NextToken
	}

	for idx := range networkInterfaces {
		ni := networkInterfaces[idx]
		networkInterfaceID := aws.StringValue(ni.NetworkInterfaceId)
		if _, ok := staticENILastReconciled[networkInterfaceID]; !ok {
			staticENILastReconciled[networkInterfaceID] = time.Now()
		}
	}

	for networkInterfaceID, lastReconciled := range staticENILastReconciled {
		if time.Since(lastReconciled) > 10*time.Minute {
			_, err = session.DeleteNetworkInterface(ctx, ec2.DeleteNetworkInterfaceInput{
				NetworkInterfaceId: aws.String(networkInterfaceID),
			})
			if err != nil {
				awsErr := ec2wrapper.RetrieveEC2Error(err)
				if awsErr != nil && awsErr.Code() == ec2wrapper.InvalidNetworkInterfaceIDNotFound {
					logger.G(ctx).Info("Static network interface was already deleted")
					delete(staticENILastReconciled, networkInterfaceID)
				}
				logger.G(ctx).WithError(err).Error("Failed to delete static ENI from AWS")
			} else {
				delete(staticENILastReconciled, networkInterfaceID)
			}
		}
	}

	return nil
}

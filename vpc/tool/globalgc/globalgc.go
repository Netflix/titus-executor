package globalgc

import (
	"context"
	"fmt"
	"time"

	"github.com/Netflix/titus-executor/ec2util"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"golang.org/x/sync/errgroup"
)

func GlobalGC(ctx context.Context, timeout, gracePeriod time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ec2client := ec2.New(session.Must(session.NewSession()))

	networkInterfaceChannel := make(chan *ec2.NetworkInterface, 1000)
	group, ctx := errgroup.WithContext(ctx)

	group.Go(func() error {
		return collectENIs(ctx, ec2client, networkInterfaceChannel)
	})

	for i := 0; i < 8; i++ {
		group.Go(func() error {
			return cleanupENIs(ctx, ec2client, networkInterfaceChannel, gracePeriod)
		})
	}

	return group.Wait()
}

func collectENIs(ctx context.Context, ec2client *ec2.EC2, ch chan *ec2.NetworkInterface) error {
	filters := []*ec2.Filter{
		{
			Name:   aws.String("description"),
			Values: aws.StringSlice([]string{vpc.NetworkInterfaceDescription}),
		},
		{
			Name:   aws.String("tag-key"),
			Values: aws.StringSlice([]string{vpc.ENICreationTimeTag}),
		},
		{
			Name:   aws.String("status"),
			Values: aws.StringSlice([]string{"available"}),
		},
	}

	describeAvailableRequest := &ec2.DescribeNetworkInterfacesInput{
		Filters:    filters,
		MaxResults: aws.Int64(1000),
	}

	for {
		describeAvailableResult, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, describeAvailableRequest)
		if err != nil {
			logger.G(ctx).WithError(err).Error("DescribeNetworkInterfaces error")
			return err
		}
		for _, networkInterface := range describeAvailableResult.NetworkInterfaces {
			ch <- networkInterface
		}
		if describeAvailableResult.NextToken == nil {
			return nil
		}
		describeAvailableRequest.SetNextToken(*describeAvailableResult.NextToken)
	}
}

func cleanupENIs(ctx context.Context, ec2client *ec2.EC2, networkInterfaceChannel chan *ec2.NetworkInterface, gracePeriod time.Duration) error {
	for i := range networkInterfaceChannel {
		if err := cleanupENI(ctx, ec2client, i, gracePeriod); err != nil {
			return err
		}
	}

	return nil
}

func cleanupENI(ctx context.Context, ec2client *ec2.EC2, eni *ec2.NetworkInterface, gracePeriod time.Duration) error {
	// TODO: Figure out which errors are fatal, and return them instead of swallowing them
	ctx = logger.WithField(ctx, "networkInterfaceId", *eni.NetworkInterfaceId)
	tags := ec2util.TagSetToMap(eni.TagSet)
	networkCreationTime, ok := tags[vpc.ENICreationTimeTag]
	if !ok {
		logger.G(ctx).Warning("ENI does not have creation time field")
		return nil
	}

	creationTime, err := time.Parse(time.RFC3339, *networkCreationTime)
	if err != nil {
		logger.G(ctx).WithField(vpc.ENICreationTimeTag, *networkCreationTime).WithError(err).Error("Cannot parse")
		return nil
	}

	if timeSinceCreation := time.Since(creationTime); timeSinceCreation < gracePeriod {
		logger.G(ctx).WithField("timeSinceCreation", timeSinceCreation.String()).Info("Not cleaning up ENI, too young")
		return nil
	}

	if *eni.Description != vpc.NetworkInterfaceDescription {
		panic(fmt.Sprintf("Interface description is %s instead of %s", *eni.Description, vpc.NetworkInterfaceDescription))
	}

	if *eni.Status != "available" {
		panic(fmt.Sprintf("Interface status is %s instead of available", *eni.Status))
	}

	logger.G(ctx).Info("Destroying ENI")
	deleteNetworkInterfaceInput := &ec2.DeleteNetworkInterfaceInput{
		NetworkInterfaceId: aws.String(*eni.NetworkInterfaceId),
	}
	_, err = ec2client.DeleteNetworkInterfaceWithContext(ctx, deleteNetworkInterfaceInput)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to delete ENI")
	}

	return nil
}

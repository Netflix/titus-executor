package globalgc

import (
	"fmt"
	"time"

	"github.com/Netflix/titus-executor/ec2util"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"gopkg.in/urfave/cli.v1"
)

type globalGcConfig struct {
	timeout           time.Duration
	timeSinceCreation time.Duration
	vpcID             string
	workers           int
}

// GlobalGC is the configuration for the command that deletes ENI which have been unattached too long
func GlobalGC() cli.Command {
	cfg := &globalGcConfig{}
	globalGc := func(parentCtx *context.VPCContext) error {
		if err := doGlobalGC(parentCtx, cfg); err != nil {
			return cli.NewMultiError(cli.NewExitError("Unable to run global gc", 1), err)
		}
		return nil
	}
	return cli.Command{ // nolint: golint
		Name:   "globalgc",
		Usage:  "Garbage collect detached ENIs",
		Action: context.WrapFunc(globalGc),
		Flags: []cli.Flag{
			cli.DurationFlag{
				Name:        "timeout",
				Usage:       "Maximum amount of time allowed running GC",
				Value:       time.Minute * 5,
				Destination: &cfg.timeout,
			},
			cli.DurationFlag{
				Name:        "time-since-creation",
				Usage:       "How long an ENI has to be created before we will clean it up",
				Value:       time.Minute * 5,
				Destination: &cfg.timeSinceCreation,
			},
			cli.StringFlag{
				Name:        "vpc-id",
				Usage:       "Optionally specify a VPC, to speed up filtering requests",
				EnvVar:      "EC2_VPC_ID",
				Value:       "",
				Destination: &cfg.vpcID,
			},
			cli.IntFlag{
				Name:        "num-workers",
				Usage:       "How many parallel workers to start to delete ENIs",
				Value:       8,
				Destination: &cfg.workers,
			},
		},
	}
}

func fetchDisconnectedENIs(parentCtx *context.VPCContext, vpcID string, networkInterfaceChannel chan *ec2.NetworkInterface) error {
	defer close(networkInterfaceChannel)
	svc := ec2.New(parentCtx.AWSSession)
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

	if vpcID != "" {
		filter := ec2.Filter{
			Name:   aws.String("vpc-id"),
			Values: aws.StringSlice([]string{vpcID}),
		}
		filters = append(filters, &filter)
	}
	describeAvailableRequest := &ec2.DescribeNetworkInterfacesInput{
		Filters:    filters,
		MaxResults: aws.Int64(1000),
	}

	// If parentCtx gets cancelled, this should bubble up and error out, but let's check just in case
	for {
		err := parentCtx.Err()
		if err != nil {
			return err
		}
		describeAvailableResult, err := svc.DescribeNetworkInterfacesWithContext(parentCtx, describeAvailableRequest)
		if err != nil {
			return err
		}
		for _, networkInterface := range describeAvailableResult.NetworkInterfaces {
			networkInterfaceChannel <- networkInterface
		}
		if describeAvailableResult.NextToken == nil {
			return nil
		}
		describeAvailableRequest.SetNextToken(*describeAvailableResult.NextToken)
	}
}

// TODO: Find fatal errors and return errors
func cleanupENI(parentCtx *context.VPCContext, svc *ec2.EC2, detachTime time.Duration, eni *ec2.NetworkInterface) error {
	ctx := parentCtx.WithField("NetworkInterfaceId", *eni.NetworkInterfaceId)
	tags := ec2util.TagSetToMap(eni.TagSet)
	networkCreationTime, ok := tags[vpc.ENICreationTimeTag]
	if !ok {
		ctx.Logger.Warning("ENI does not have creation time field")
		return nil
	}
	creationTime, err := time.Parse(time.RFC3339, *networkCreationTime)
	if err != nil {
		ctx.Logger.WithField(vpc.ENICreationTimeTag, *networkCreationTime).WithError(err).Error("Cannot parse")
		return nil
	}
	timeSinceCreation := time.Since(creationTime)
	if timeSinceCreation < detachTime {
		ctx.Logger.WithField("timeSinceCreation", timeSinceCreation.String()).Debug("Not cleaning up ENI, too young")
		return nil
	}

	if *eni.Description != vpc.NetworkInterfaceDescription {
		panic(fmt.Sprintf("Interface description is %s instead of %s", *eni.Description, vpc.NetworkInterfaceDescription))
	}
	if *eni.Status != "available" {
		panic(fmt.Sprintf("Interface status is %s instead of available", *eni.Status))
	}

	parentCtx.Logger.WithField("eni-name", *eni.NetworkInterfaceId).Info("Destroying ENI")
	deleteNetworkInterfaceInput := &ec2.DeleteNetworkInterfaceInput{
		NetworkInterfaceId: aws.String(*eni.NetworkInterfaceId),
	}
	_, err = svc.DeleteNetworkInterfaceWithContext(ctx, deleteNetworkInterfaceInput)
	if err != nil {
		parentCtx.Logger.WithError(err).Error("Unable to delete ENI")
	}

	return nil
}

func cleanupENIs(parentCtx *context.VPCContext, detachTime time.Duration, networkInterfaceChannel chan *ec2.NetworkInterface) error {
	svc := ec2.New(parentCtx.AWSSession)
	for eni := range networkInterfaceChannel {
		if err := cleanupENI(parentCtx, svc, detachTime, eni); err != nil {
			return err
		}
	}
	return nil
}

func doGlobalGC(parentCtx *context.VPCContext, cfg *globalGcConfig) error {
	grp, ctx := parentCtx.ErrGroup()
	networkInterfaceChannel := make(chan *ec2.NetworkInterface, 100000)
	grp.Go(func() error {
		return fetchDisconnectedENIs(ctx, cfg.vpcID, networkInterfaceChannel)
	})

	for i := 0; i < cfg.workers; i++ {
		grp.Go(func() error {
			return cleanupENIs(ctx, cfg.timeSinceCreation, networkInterfaceChannel)
		})
	}

	return grp.Wait()
}

package backfilleni

import (
	"time"

	"github.com/Netflix/titus-executor/ec2util"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/go-multierror"
	"gopkg.in/urfave/cli.v1"
)

type backfillConfiguration struct {
	TagChunkSize int
	Timeout      time.Duration
	VPCID        string
}

// BackfillEni is the configuration for the command that labels creation time on new ENIs
func BackfillEni() cli.Command {
	cfg := &backfillConfiguration{}
	backkFillEni := func(parentCtx *context.VPCContext) error {
		if err := doBackfillEni(parentCtx, cfg); err != nil {
			return cli.NewMultiError(cli.NewExitError("Unable to generate backfill", 1), err)
		}
		return nil
	}
	return cli.Command{ // nolint: golint
		Name:   "backfill-eni-labels",
		Usage:  "For ENIs which do not have a creation timestamp tag, this will go ahead and do its best to backfill it",
		Action: context.WrapFunc(backkFillEni),
		Flags: []cli.Flag{
			cli.IntFlag{
				Name:        "tag-chunk-size",
				Value:       50,
				Destination: &cfg.TagChunkSize,
			},
			cli.DurationFlag{
				Name:        "timeout",
				Value:       30 * time.Minute,
				Destination: &cfg.Timeout,
			},
			cli.StringFlag{
				Name:        "vpc-id",
				Usage:       "Optionally specify a VPC, to speed up filtering requests",
				EnvVar:      "EC2_VPC_ID",
				Value:       "",
				Destination: &cfg.VPCID,
			},
		},
	}
}

func getENIs(parentCtx *context.VPCContext, cfg *backfillConfiguration, svc *ec2.EC2) ([]*ec2.NetworkInterface, error) {
	filters := []*ec2.Filter{
		{
			Name:   aws.String("description"),
			Values: aws.StringSlice([]string{vpc.NetworkInterfaceDescription}),
		},
		{
			Name:   aws.String("status"),
			Values: aws.StringSlice([]string{"available"}),
		},
	}

	if cfg.VPCID != "" {
		vpcFilter := &ec2.Filter{
			Name:   aws.String("vpc-id"),
			Values: aws.StringSlice([]string{cfg.VPCID}),
		}
		filters = append(filters, vpcFilter)
	}

	describeAvailableRequest := &ec2.DescribeNetworkInterfacesInput{
		Filters: filters,
		// 1000 is the maximum number of results
		MaxResults: aws.Int64(1000),
	}

	untaggedEnis := []*ec2.NetworkInterface{}
	for {
		describeAvailableResponse, err := svc.DescribeNetworkInterfacesWithContext(parentCtx, describeAvailableRequest)
		if err != nil {
			return nil, err
		}
		untaggedEnis = append(untaggedEnis, describeAvailableResponse.NetworkInterfaces...)

		if describeAvailableResponse.NextToken == nil {
			return untaggedEnis, nil
		}
		describeAvailableRequest.SetNextToken(*describeAvailableResponse.NextToken)
	}
}

func filterUntaggedInterfaces(enis []*ec2.NetworkInterface) []*ec2.NetworkInterface {
	untaggedENIs := []*ec2.NetworkInterface{}
	for _, eni := range enis {
		tags := ec2util.TagSetToMap(eni.TagSet)
		if _, ok := tags[vpc.ENICreationTimeTag]; !ok {
			untaggedENIs = append(untaggedENIs, eni)
		}
	}
	return untaggedENIs
}

func doBackfillEni(parentCtx *context.VPCContext, cfg *backfillConfiguration) error {
	svc := ec2.New(parentCtx.AWSSession)

	ctx, cancel := parentCtx.WithTimeout(cfg.Timeout)
	defer cancel()

	ctx.Logger.Info("Fetching untagged ENIs")

	enis, err := getENIs(ctx, cfg, svc)
	if err != nil {
		return err
	}

	untaggedEnis := filterUntaggedInterfaces(enis)
	ctx.Logger.WithField("count", len(untaggedEnis)).Info("Found untagged ENIs")

	now := time.Now()
	// We do this because even though the CreateTagsInput call accepts multiple resources, if one of the resources
	// is missing, it ends up causing the whole thing to fail
	var result *multierror.Error

	for _, untaggedENI := range untaggedEnis {
		err = tagENI(parentCtx, untaggedENI, svc, now)
		if err != nil {
			result = multierror.Append(result, err)
		}
	}
	return result.ErrorOrNil()
}

func tagENI(parentCtx *context.VPCContext, eni *ec2.NetworkInterface, svc *ec2.EC2, now time.Time) error {
	ctx := parentCtx.Logger.WithField("eni", *eni.NetworkInterfaceId)
	ctx.Info("Labeling ENI")

	createTagsInput := &ec2.CreateTagsInput{
		Resources: aws.StringSlice([]string{*eni.NetworkInterfaceId}),
		Tags: []*ec2.Tag{
			{
				Key:   aws.String(vpc.ENICreationTimeTag),
				Value: aws.String(now.Format(time.RFC3339)),
			},
		},
	}
	// TODO:
	// Joe? Do you how this deals with (potential) failure if one ENI doesn't exist
	// svc.CreateTagsWithContext(parentCtx, createTagsInput)
	_, err := svc.CreateTagsWithContext(parentCtx, createTagsInput)
	if err == nil {
		ctx.Info("Labeled ENI")
		return nil
	}
	ctx.Logger.WithError(err).Warning("Failed to label ENI")
	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "InvalidNetworkInterfaceID.NotFound" {
		return nil
	}
	return err
}

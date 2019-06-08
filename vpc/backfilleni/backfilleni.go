package backfilleni

import (
	"regexp"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"context"

	"github.com/Netflix/titus-executor/ec2util"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
)

var (
	eniErrorRegex = regexp.MustCompile(`networkInterface ID '(eni-[0-f]+)' does not exist`)
)

// BackfillEni is the configuration for the command that labels creation time on new ENIs
func BackfillEni(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	networkInterfaceChannel := make(chan ec2.NetworkInterface, 10000)
	group, errGroupCtx := errgroup.WithContext(ctx)

	ec2client := ec2.New(session.Must(session.NewSession()))

	group.Go(func() error {
		return getENIs(errGroupCtx, ec2client, networkInterfaceChannel)
	})

	group.Go(func() error {
		return backfillENILoop(errGroupCtx, ec2client, group, networkInterfaceChannel)
	})

	return group.Wait()
}

func getENIs(ctx context.Context, ec2client *ec2.EC2, ch chan ec2.NetworkInterface) error {
	defer close(ch)

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

	describeAvailableRequest := &ec2.DescribeNetworkInterfacesInput{
		Filters: filters,
		// 1000 is the maximum number of results allowed
		MaxResults: aws.Int64(1000),
	}

	for ctx.Err() == nil {
		describeAvailableResponse, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, describeAvailableRequest)
		if err != nil {
			return errors.Wrap(err, "Unable to describe network interfaces")
		}

		for idx := range describeAvailableResponse.NetworkInterfaces {
			networkInterface := describeAvailableResponse.NetworkInterfaces[idx]
			tags := ec2util.TagSetToMap(networkInterface.TagSet)
			if _, ok := tags[vpc.ENICreationTimeTag]; !ok {
				ch <- *networkInterface
			}
		}

		if describeAvailableResponse.NextToken == nil {
			return nil
		}
		describeAvailableRequest.SetNextToken(*describeAvailableResponse.NextToken)
	}

	return errors.Wrap(ctx.Err(), "Context error while enumerating ENIs")
}

func backfillENILoop(ctx context.Context, ec2client *ec2.EC2, group *errgroup.Group, ch chan ec2.NetworkInterface) error {
	// We don't abort on the first error because even though the CreateTagsInput call accepts multiple resources,
	// if one of the resources is missing, it ends up causing the whole thing to fail.
	networkInterfaces := make(map[string]ec2.NetworkInterface, 50)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case networkInterface, ok := <-ch:
			if !ok {
				// The channel is closed, gotta wrap up
				if len(networkInterfaces) > 0 {
					return backfillENIs(ctx, ec2client, networkInterfaces)
				}
				return nil
			}
			logger.G(ctx).WithField("eni", networkInterface).Info("Found untagged ENI")
			networkInterfaces[*networkInterface.NetworkInterfaceId] = networkInterface

			if len(networkInterfaces) > 50 {
				tmp := networkInterfaces
				group.Go(func() error {
					return backfillENIs(ctx, ec2client, tmp)
				})
				networkInterfaces = make(map[string]ec2.NetworkInterface, 50)

			}
		}
	}
}

func backfillENIs(ctx context.Context, ec2client *ec2.EC2, networkInterfaces map[string]ec2.NetworkInterface) error {
	now := time.Now()

	networkInterfaceIds := make([]string, 0, len(networkInterfaces))
	for _, iface := range networkInterfaces {
		networkInterfaceIds = append(networkInterfaceIds, *iface.NetworkInterfaceId)
	}

	logger.G(ctx).WithField("enis", networkInterfaceIds).Debug("Attempting to tag ENIs")
	createTagsInput := &ec2.CreateTagsInput{
		Resources: aws.StringSlice(networkInterfaceIds),
		Tags: []*ec2.Tag{
			{
				Key:   aws.String(vpc.ENICreationTimeTag),
				Value: aws.String(now.Format(time.RFC3339)),
			},
		},
	}

	_, err := ec2client.CreateTagsWithContext(ctx, createTagsInput)
	if err == nil {
		return nil
	}

	logger.G(ctx).WithError(err).Error("Error while tagging ENIs")

	awsErr, ok := err.(awserr.Error)
	if !ok {
		return errors.Wrap(err, "Received non-AWS related error while tagging ENIs")
	}

	if awsErr.Code() != "InvalidNetworkInterfaceID.NotFound" {
		return errors.Wrap(err, "Received AWS related error while tagging ENIs")
	}

	submatch := eniErrorRegex.FindStringSubmatch(awsErr.Message())
	if submatch == nil {
		return errors.Wrap(awsErr, "Cannot parse InvalidNetworkInterfaceID.NotFound error from AWS")
	}

	badENI := submatch[1]
	delete(networkInterfaces, badENI)
	logger.G(ctx).WithField("eni", badENI).Warning("Interface deleted during work. Retrying")
	return backfillENIs(ctx, ec2client, networkInterfaces)
}

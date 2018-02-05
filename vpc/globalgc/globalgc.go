package globalgc

import (
	"fmt"
	"time"

	"github.com/Netflix/titus-executor/vpc/context"
	"github.com/Netflix/titus-executor/vpc/setup"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"gopkg.in/urfave/cli.v1"
)

const (
	markTag = "titus-gc-mark-time"
)

var GlobalGC = cli.Command{ // nolint: golint
	Name:   "globalgc",
	Usage:  "Garbage collect detached ENIs",
	Action: context.WrapFunc(globalGc),
	Flags: []cli.Flag{
		cli.DurationFlag{
			Name:  "timeout",
			Usage: "Maximum amount of time allowed running GC",
			Value: time.Minute * 5,
		},
		cli.DurationFlag{
			Name:  "detach-time",
			Usage: "How long an ENI has to be detached before we will clean it up",
			Value: time.Minute * 30,
		},
	},
}

func globalGc(parentCtx *context.VPCContext) error {
	timeout := parentCtx.CLIContext.Duration("timeout")
	ctx, cancel := parentCtx.WithTimeout(timeout)
	defer cancel()

	minDetachTime := parentCtx.CLIContext.Duration("detach-time")

	if err := doGlobalGc(ctx, minDetachTime); err != nil {
		return cli.NewMultiError(cli.NewExitError("Unable to run GC", 1), err)
	}

	return nil
}

func doGlobalGc(parentCtx *context.VPCContext, minDetachTime time.Duration) error {
	ec2Client := ec2.New(parentCtx.AWSSession)

	describeAvailableRequest := &ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("description"),
				Values: aws.StringSlice([]string{setup.NetworkInterfaceDescription}),
			},
			{
				Name:   aws.String("status"),
				Values: aws.StringSlice([]string{"available"}),
			},
		},
	}

	networkInterfaces, err := ec2Client.DescribeNetworkInterfacesWithContext(parentCtx, describeAvailableRequest)
	if err != nil {
		return err
	}

	now := time.Now()
	// Get the candidates, and selected
	candidates, selected := markAndCollect(parentCtx, networkInterfaces, minDetachTime, now)
	parentCtx.Logger.Info("Going to GC: ", selected)
	// Delete the selected
	err = deleteSelected(parentCtx, selected)
	if err != nil {
		return err
	}

	// Mark the candidates
	if len(candidates) > 0 {
		err = doMark(parentCtx, candidates, now, ec2Client)
		if err != nil {
			return err
		}
	}

	// Remove incorrectly marked interfaces
	describeMarkedRequest := &ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("description"),
				Values: aws.StringSlice([]string{setup.NetworkInterfaceDescription}),
			},
			{
				Name:   aws.String("status"),
				Values: aws.StringSlice([]string{"in-use"}),
			},
			{
				Name:   aws.String("tag-key"),
				Values: aws.StringSlice([]string{markTag}),
			},
		},
	}

	markedNetworkInterfaces, err := ec2Client.DescribeNetworkInterfacesWithContext(parentCtx, describeMarkedRequest)
	if err != nil {
		return err
	}

	attachedInterfaces := extractNetworkInterfaces(markedNetworkInterfaces)
	if len(attachedInterfaces) > 0 {
		parentCtx.Logger.Info("Removing gc mark from interfaces: ", attachedInterfaces)
		deleteTagsInput := &ec2.DeleteTagsInput{
			Resources: attachedInterfaces,
			Tags: []*ec2.Tag{
				{
					Key: aws.String(markTag),
				},
			},
		}
		_, err = ec2Client.DeleteTagsWithContext(parentCtx, deleteTagsInput)

		if err != nil {
			return err
		}
	}

	return nil
}

func doMark(parentCtx *context.VPCContext, candidates []string, now time.Time, ec2Client *ec2.EC2) error {
	// Split it up into chunks of 10
	for i := 0; i*10 < len(candidates); i++ {
		pageBegin := i * 10
		pageEnd := min(len(candidates), (i+1)*10)
		parentCtx.Logger.Info("Marking candidates: ", candidates[pageBegin:pageEnd])
		createTagsInput := &ec2.CreateTagsInput{
			Resources: aws.StringSlice(candidates[pageBegin:pageEnd]),
			Tags: []*ec2.Tag{
				{
					Key:   aws.String(markTag),
					Value: aws.String(now.Format(time.RFC3339)),
				},
			},
		}
		_, err := ec2Client.CreateTagsWithContext(parentCtx, createTagsInput)
		// Is this an actual fatal error?
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "InvalidNetworkInterfaceID.NotFound" {
				parentCtx.Logger.Warning("Unable to process batch because: ", err)
			} else {
				return err
			}
		}
	}

	return nil
}

func extractNetworkInterfaces(networkInterfaces *ec2.DescribeNetworkInterfacesOutput) []*string {
	ret := make([]*string, len(networkInterfaces.NetworkInterfaces))
	for idx, iface := range networkInterfaces.NetworkInterfaces {
		ret[idx] = iface.NetworkInterfaceId
	}
	return ret
}

// Returns ENI IDs that match the criteria to be GCd, and marks ENIs which could be elected for the next generation of GC
func markAndCollect(parentCtx *context.VPCContext, networkInterfaces *ec2.DescribeNetworkInterfacesOutput, minDetachTime time.Duration, now time.Time) ([]string, []string) {
	candidates := []string{}
	selected := []string{}

	for _, iface := range networkInterfaces.NetworkInterfaces {
		// AWS's APIs can return inconsistent results, so these might panic. If so, we should run again.
		if *iface.Description != setup.NetworkInterfaceDescription {
			panic(fmt.Sprintf("Interface description is %s instead of %s", *iface.Description, setup.NetworkInterfaceDescription))
		}
		if *iface.Status != "available" {
			panic(fmt.Sprintf("Interface status is %s instead of available", *iface.Status))
		}
		ifaceTags := tagSetToMap(iface.TagSet)
		if markTagValue, ok := ifaceTags[markTag]; ok && markTagValue != nil {
			markTimestamp, err := time.Parse(time.RFC3339, *markTagValue)
			if err != nil {
				// This shouldn't happen.
				parentCtx.Logger.Error("Unable to parse marktimestamp: ", markTagValue)
			} else if now.Sub(markTimestamp) > minDetachTime {
				parentCtx.Logger.Debug("Marking interface as selected: ", *iface)
				selected = append(selected, *iface.NetworkInterfaceId)
			}
		} else {
			parentCtx.Logger.Debug("Marking interface as candidate: ", *iface)
			candidates = append(candidates, *iface.NetworkInterfaceId)
		}
	}

	return candidates, selected
}

func tagSetToMap(tagSet []*ec2.Tag) map[string]*string {
	ret := make(map[string]*string)
	// No tags
	if tagSet == nil {
		return ret
	}
	for _, tag := range tagSet {
		ret[*tag.Key] = tag.Value
	}
	return ret
}

func deleteSelected(parentCtx *context.VPCContext, selected []string) error {
	ec2Client := ec2.New(parentCtx.AWSSession)
	for _, iface := range selected {
		ctx := parentCtx.WithField("iface", iface)
		deleteNetworkInterfaceInput := &ec2.DeleteNetworkInterfaceInput{
			NetworkInterfaceId: aws.String(iface),
		}
		ctx.Logger.Debug("Deleting interface")
		_, err := ec2Client.DeleteNetworkInterfaceWithContext(ctx, deleteNetworkInterfaceInput)
		if err != nil {
			return err
		}
		ctx.Logger.Debug("Deleted interface")
	}
	return nil
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

package service

import (
	"context"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
)

func doesENIExist(ctx context.Context, session *ec2wrapper.EC2Session, networkInterfaceID, originalDescription string) (bool, error) {
	// Does this ENI really exist?
	_, err := session.ModifyNetworkInterfaceAttribute(ctx, ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: aws.String(networkInterfaceID),
		Description: &ec2.AttributeValue{
			Value: aws.String(originalDescription),
		},
	})
	if err == nil {
		logger.G(ctx).Warn("Was able to find interface via modify interface attribute, skipping")
		return true, nil
	}
	awsErr := ec2wrapper.RetrieveEC2Error(err)
	if awsErr == nil {
		logger.G(ctx).WithError(err).Error("Experienced non-AWS error while calling modify network interface attribute")
		return false, err
	}

	if awsErr.Code() == ec2wrapper.InvalidNetworkInterfaceIDNotFound {
		return false, nil
	}

	return false, err
}

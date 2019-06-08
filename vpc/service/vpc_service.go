package service

import (
	"sync"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)
import "context"

type key struct {
	accountID string
	region    string
}

type vpcService struct {
	metrics      *statsd.Client
	sessionsLock sync.RWMutex
	sessions     map[key]*session.Session
}

func (vpcService *vpcService) getSession(ctx context.Context, instanceIdentity *vpcapi.InstanceIdentity) *session.Session {
	// TODO: Do get called identity, and check if assumerole is required for account assumption
	sessionKey := key{
		region:    instanceIdentity.Region,
		accountID: instanceIdentity.AccountID,
	}
	vpcService.sessionsLock.RLock()
	instanceSession, ok := vpcService.sessions[sessionKey]
	vpcService.sessionsLock.RUnlock()
	if ok {
		return instanceSession
	}

	config := &aws.Config{}
	if instanceIdentity.Region != "" {
		config.Region = &instanceIdentity.Region
	}

	// TODO: Return an error here
	instanceSession = session.Must(session.NewSession(config))

	vpcService.sessionsLock.Lock()
	defer vpcService.sessionsLock.Unlock()
	vpcService.sessions[sessionKey] = instanceSession

	return instanceSession
}

func (vpcService *vpcService) getInstance(ctx context.Context, instanceIdentity *vpcapi.InstanceIdentity) (*ec2.EC2, *ec2.Instance, error) {
	ec2client := ec2.New(vpcService.getSession(ctx, instanceIdentity))
	describeInstancesOutput, err := ec2client.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{instanceIdentity.GetInstanceID()}),
	})

	if err != nil {
		logger.G(ctx).Error("Could not get EC2 Instance")
		switch awsErr := err.(type) {
		case awserr.Error:
			if awsErr.Code() == "InvalidInstanceID.NotFound" {
				return nil, nil, status.Error(codes.NotFound, awsErr.Error())
			}
		default:
			return nil, nil, err
		}
	}

	if describeInstancesOutput.Reservations == nil || len(describeInstancesOutput.Reservations) == 0 {
		return nil, nil, status.Error(codes.NotFound, "Describe Instances returned 0 reservations")
	}
	if describeInstancesOutput.Reservations[0].Instances == nil || len(describeInstancesOutput.Reservations[0].Instances) == 0 {
		return nil, nil, status.Error(codes.NotFound, "Describe Instances returned 0 instances")
	}

	return ec2client, describeInstancesOutput.Reservations[0].Instances[0], nil

}

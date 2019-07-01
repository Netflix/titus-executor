package ec2wrapper

import (
	"context"
	"fmt"
	"time"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_ EC2InstanceSession = (*ec2InstanceSession)(nil)
	_ error              = (*ErrInterfaceByIdxNotFound)(nil)
)

type ec2InstanceSession struct {
	*ec2BaseSession
	instanceIdentity *vpcapi.InstanceIdentity
}

type ErrInterfaceByIdxNotFound struct {
	instance  *ec2.Instance
	deviceIdx uint32
}

func (e *ErrInterfaceByIdxNotFound) Error() string {
	return fmt.Sprintf("Interface at index %d not found on instance %s", e.deviceIdx, aws.StringValue(e.instance.InstanceId))
}

func IsErrInterfaceByIdxNotFound(err error) bool {
	_, ok := err.(*ErrInterfaceByIdxNotFound)
	return ok
}

// GetInterfaceByIdx returns an interface attached at the specific index of the node. If the cache strategy includes
// fetching from cache, but the interface is not present, we will try to invalidate the cache, and refetch
// once.
//
// If we don't find an interface attached, the function will return nil, with an ErrInterfaceByIdxNotFound
func (s *ec2InstanceSession) GetInterfaceByIdx(ctx context.Context, deviceIdx uint32) (EC2NetworkInterfaceSession, error) {
	// Fetch the interface from the instance from cache. If the cached instance doesn't have the interface
	// attached, then try to refresh the instance cache from cache

	instance, err := s.GetInstance(ctx, UseCache)
	if err != nil {
		return nil, err
	}

	for _, ni := range instance.NetworkInterfaces {
		if aws.Int64Value(ni.Attachment.DeviceIndex) == int64(deviceIdx) {
			return s.GetSessionFromNetworkInterface(ctx, ni)
		}
	}

	instance, err = s.GetInstance(ctx, InvalidateCache|StoreInCache)
	if err != nil {
		return nil, err
	}

	for _, ni := range instance.NetworkInterfaces {
		if aws.Int64Value(ni.Attachment.DeviceIndex) == int64(deviceIdx) {
			return s.GetSessionFromNetworkInterface(ctx, ni)
		}
	}
	return nil, &ErrInterfaceByIdxNotFound{instance: instance, deviceIdx: deviceIdx}
}

func (s *ec2InstanceSession) GetSessionFromNetworkInterface(ctx context.Context, instanceNetworkInterface *ec2.InstanceNetworkInterface) (EC2NetworkInterfaceSession, error) {
	return &ec2NetworkInterfaceSession{
		ec2BaseSession:           s.ec2BaseSession,
		instanceNetworkInterface: instanceNetworkInterface,
	}, nil
}

func (s *ec2InstanceSession) Region(ctx context.Context) (string, error) {
	if s.instanceIdentity.Region != "" {
		return s.instanceIdentity.Region, nil
	}
	// TODO: Try to retrieve the region from the instance identity document.

	return "", errors.New("Cannot find instance region")
}

func (s *ec2InstanceSession) GetInstance(ctx context.Context, strategy CacheStrategy) (*ec2.Instance, error) {
	ctx, span := trace.StartSpan(ctx, "getInstance")
	defer span.End()
	start := time.Now()
	ctx, err := tag.New(ctx, tag.Upsert(keyInstance, s.instanceIdentity.GetInstanceID()))
	if err != nil {
		return nil, err
	}
	stats.Record(ctx, getInstanceCount.M(1))

	if strategy&InvalidateCache > 0 {
		stats.Record(ctx, invalidateInstanceFromCache.M(1))
		s.instanceCache.Remove(s.instanceIdentity.InstanceID)
	}
	if strategy&FetchFromCache > 0 {
		stats.Record(ctx, getInstanceFromCache.M(1))
		instance, ok := s.instanceCache.Get(s.instanceIdentity.InstanceID)
		if ok {
			stats.Record(ctx, getInstanceFromCacheSuccess.M(1), getInstanceSuccess.M(1))
			return instance.(*ec2.Instance), nil
		}
	}

	ec2client := ec2.New(s.session)
	describeInstancesOutput, err := ec2client.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{s.instanceIdentity.GetInstanceID()}),
	})

	if err != nil {
		logger.G(ctx).WithError(err).WithField("ec2InstanceId", s.instanceIdentity.GetInstanceID()).Error("Could not get EC2 Instance")
		return nil, handleEC2Error(err, span)
	}

	if describeInstancesOutput.Reservations == nil || len(describeInstancesOutput.Reservations) == 0 {
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeNotFound,
			Message: "Describe Instances returned 0 reservations",
		})
		return nil, status.Error(codes.NotFound, "Describe Instances returned 0 reservations")
	}
	if describeInstancesOutput.Reservations[0].Instances == nil || len(describeInstancesOutput.Reservations[0].Instances) == 0 {
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeNotFound,
			Message: "Describe Instances returned 0 instances",
		})
		return nil, status.Error(codes.NotFound, "Describe Instances returned 0 instances")
	}

	stats.Record(ctx, getInstanceMs.M(float64(time.Since(start).Nanoseconds())), getInstanceSuccess.M(1))
	if strategy&StoreInCache > 0 {
		stats.Record(ctx, storedInstanceInCache.M(1))
		s.instanceCache.Add(s.instanceIdentity.InstanceID, describeInstancesOutput.Reservations[0].Instances[0])
	}
	return describeInstancesOutput.Reservations[0].Instances[0], nil
}

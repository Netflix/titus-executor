package ec2wrapper

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"go.opencensus.io/trace"
)

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

func GetInterfaceByIdxWithRetries(ctx context.Context, session *EC2Session, instance *ec2.Instance, deviceIdx uint32) (*ec2.InstanceNetworkInterface, error) {
	ctx, span := trace.StartSpan(ctx, "GetInterfaceByIdxWithRetries")
	defer span.End()
	// Fetch the interface from the instance from cache. If the cached instance doesn't have the interface
	// attached, then try to refresh the instance cache from cache
	for _, ni := range instance.NetworkInterfaces {
		if aws.Int64Value(ni.Attachment.DeviceIndex) == int64(deviceIdx) {
			return ni, nil
		}
	}

	// Retry / refresh the interface
	instance, _, err := session.GetInstance(ctx, aws.StringValue(instance.InstanceId), true)
	if err != nil {
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeUnknown,
			Message: err.Error(),
		})
		return nil, err
	}
	for _, ni := range instance.NetworkInterfaces {
		if aws.Int64Value(ni.Attachment.DeviceIndex) == int64(deviceIdx) {
			return ni, nil
		}
	}
	err = &ErrInterfaceByIdxNotFound{instance: instance, deviceIdx: deviceIdx}
	span.SetStatus(trace.Status{
		Code:    trace.StatusCodeUnknown,
		Message: err.Error(),
	})
	return nil, err
}

// Deprecated
func RegionFromAZ(az string) string {
	return az[:len(az)-1]
}

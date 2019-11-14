package ec2wrapper

import (
	"context"
	"fmt"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/awserr"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/request"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func HandleEC2Error(err error, span *trace.Span) error {
	if err == nil {
		span.SetStatus(trace.Status{
			Code: trace.StatusCodeOK,
		})
		return nil
	}
	switch awsErr := err.(type) {
	case awserr.Error:
		switch awsErr.Code() {
		case "InvalidSubnetID.NotFound", "InvalidInstanceID.NotFound":
			span.SetStatus(trace.Status{
				Code:    trace.StatusCodeNotFound,
				Message: awsErr.Error(),
			})
			return status.Error(codes.NotFound, awsErr.Error())
		case "Client.RequestLimitExceeded":
			span.SetStatus(trace.Status{
				Code:    trace.StatusCodeNotFound,
				Message: awsErr.Error(),
			})
			return status.Error(codes.ResourceExhausted, awsErr.Error())
		case request.CanceledErrorCode:
			span.SetStatus(trace.Status{
				Code:    trace.StatusCodeCancelled,
				Message: awsErr.Error(),
			})
			return status.Error(codes.Canceled, awsErr.Error())
		default:
			reterr := fmt.Sprintf("Error calling AWS: %s", awsErr.Error())
			span.SetStatus(trace.Status{
				Code:    trace.StatusCodeUnknown,
				Message: reterr,
			})
			return status.Error(codes.Unknown, reterr)
		}
	default:
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeUnknown,
			Message: err.Error(),
		})
		return err
	}
}

func GetInterfaceByIdxWithRetries(ctx context.Context, session *EC2Session, instance *ec2.Instance, deviceIdx uint32) (*ec2.InstanceNetworkInterface, error) {
	// Fetch the interface from the instance from cache. If the cached instance doesn't have the interface
	// attached, then try to refresh the instance cache from cache
	for _, ni := range instance.NetworkInterfaces {
		if aws.Int64Value(ni.Attachment.DeviceIndex) == int64(deviceIdx) {
			return ni, nil
		}
	}

	// Retry / refresh the interface
	instance, _, err := session.GetInstance(ctx, aws.StringValue(instance.InstanceId), InvalidateCache|StoreInCache)
	if err != nil {
		return nil, err
	}
	for _, ni := range instance.NetworkInterfaces {
		if aws.Int64Value(ni.Attachment.DeviceIndex) == int64(deviceIdx) {
			return ni, nil
		}
	}
	return nil, &ErrInterfaceByIdxNotFound{instance: instance, deviceIdx: deviceIdx}
}

func RegionFromAZ(az string) string {
	return az[:len(az)-1]
}

package ec2wrapper

import (
	"context"
	"fmt"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/awserr"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/request"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
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

func RetrieveEC2Error(err error) awserr.Error {
	if err == nil {
		return nil
	}
	type causer interface {
		Cause() error
	}

	for err != nil {
		// Check if the cause is an aws error
		awsErr, ok := err.(awserr.Error)
		if ok {
			return awsErr
		}

		cause, ok := err.(causer)
		if !ok {
			break
		}

		err = cause.Cause()
	}
	return nil
}

func RetrieveRequestFailure(err error) awserr.RequestFailure {
	if err == nil {
		return nil
	}
	type causer interface {
		Cause() error
	}

	for err != nil {
		// Check if the cause is an aws error
		requestFailure, ok := err.(awserr.RequestFailure)
		if ok {
			return requestFailure
		}

		cause, ok := err.(causer)
		if !ok {
			break
		}

		err = cause.Cause()
	}
	return nil
}

// Sets the span to the status of the EC2 errors, and converts it into a GRPC Status error,
// It subsequently cannot be wrapped, with preservation of the awserr as the original caller
func HandleEC2Error(err error, span *trace.Span) error {
	awsErr := RetrieveEC2Error(err)
	if awsErr == nil {
		// This was a non-AWS error, fallback
		tracehelpers.SetStatus(err, span)
		return err
	}

	switch awsErr.Code() {
	case "InvalidSubnetID.NotFound", "InvalidInstanceID.NotFound", "InvalidNetworkInterfaceID.NotFound":
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeNotFound,
			Message: err.Error(),
		})
		return status.Error(codes.NotFound, awsErr.Error())
	case "Client.RequestLimitExceeded":
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeResourceExhausted,
			Message: err.Error(),
		})
		return status.Error(codes.ResourceExhausted, awsErr.Error())
	case request.CanceledErrorCode:
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeCancelled,
			Message: err.Error(),
		})
		return status.Error(codes.Canceled, awsErr.Error())
	case request.ErrCodeResponseTimeout:
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeDeadlineExceeded,
			Message: err.Error(),
		})
		return status.Error(codes.DeadlineExceeded, awsErr.Error())

	default:
		reterr := fmt.Sprintf("Unknown error calling AWS: %s", err.Error())
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeUnknown,
			Message: reterr,
		})
		return status.Error(codes.Unknown, reterr)
	}
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

package ec2wrapper

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func handleEC2Error(err error, span *trace.Span) error {
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

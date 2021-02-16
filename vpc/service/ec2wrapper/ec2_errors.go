package ec2wrapper

import (
	"fmt"

	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	InvalidNetworkInterfaceIDNotFound = "InvalidNetworkInterfaceID.NotFound"
	InvalidAssociationIDNotFound      = "InvalidAssociationID.NotFound"
	InvalidGroupNotFound              = "InvalidGroup.NotFound"
	InvalidSubnetIDNotFound           = "InvalidSubnetID.NotFound"
	InvalidInstanceIDNotFound         = "InvalidInstanceID.NotFound"
	ClientRequestLimitExceeded        = "Client.RequestLimitExceeded"
)

func RetrieveEC2Error(err error) awserr.Error {
	type causer interface {
		Cause() error
	}

	for err != nil {
		// Check if the cause is an aws error
		awsErr, ok := err.(awserr.Error)
		if ok {
			return awsErr
		}

		if cause, ok := err.(causer); ok {
			err = cause.Cause()
			continue
		}

		// Otherwise try to unwrap the error
		err = errors.Unwrap(err)
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

		if cause, ok := err.(causer); ok {
			err = cause.Cause()
			continue
		}

		// Otherwise try to unwrap the error
		err = errors.Unwrap(err)
	}
	return nil
}

type wrappedRequestFailureError struct {
	err awserr.RequestFailure
}

func (r *wrappedRequestFailureError) Unwrap() error {
	if r.err.StatusCode() >= 500 && r.err.StatusCode() < 600 {
		// We should retry this error
		return vpcerrors.NewRetryable(r.err)
	}

	if r.err.StatusCode() >= 400 && r.err.StatusCode() < 500 {
		// We should retry this error
		return vpcerrors.NewPersistentError(r.err)
	}

	return r.err
}

func (r *wrappedRequestFailureError) Error() string {
	return r.err.Error()
}

func (r *wrappedRequestFailureError) GRPCStatus() *status.Status {
	code, msg := decodeError(r.err)
	return status.New(code, msg)
}

type wrappedEC2Error struct {
	err awserr.Error
}

func (w *wrappedEC2Error) Error() string {
	return w.err.Error()
}

func (w *wrappedEC2Error) Unwrap() error {
	return w.err
}

func (w *wrappedEC2Error) GRPCStatus() *status.Status {
	code, msg := decodeError(w.err)
	return status.New(code, msg)
}

func IsRequestFailure(err error) bool {
	return RetrieveRequestFailure(err) != nil
}

func IsAWSErr(err error) bool {
	return RetrieveEC2Error(err) != nil
}

func decodeError(e awserr.Error) (codes.Code, string) {
	switch e.Code() {
	case InvalidNetworkInterfaceIDNotFound, InvalidAssociationIDNotFound, InvalidGroupNotFound, InvalidSubnetIDNotFound, InvalidInstanceIDNotFound:
		return codes.NotFound, e.Error()
	case ClientRequestLimitExceeded:
		return codes.ResourceExhausted, e.Error()
	case request.CanceledErrorCode:
		return trace.StatusCodeCancelled, e.Error()
	case request.ErrCodeResponseTimeout:
		return codes.DeadlineExceeded, e.Error()
	default:
		return codes.Unknown, fmt.Sprintf("Unknown error calling AWS: %s", e.Error())
	}
}

// Returns an error, with aspects from the vpcerrors library
func WrapEC2Error(err error) error {
	if err == nil {
		return nil
	}

	if e := RetrieveRequestFailure(err); e != nil {
		err = &wrappedRequestFailureError{err: e}
		return err
	}

	if e := RetrieveEC2Error(err); e != nil {
		err = &wrappedEC2Error{err: e}
		return err
	}

	return err
}

// Sets the span to the status of the EC2 errors, and returns a wrapped error
func HandleEC2Error(err error, span *trace.Span) error {
	if err == nil {
		return nil
	}

	if e := RetrieveRequestFailure(err); e != nil {
		span.AddAttributes(
			trace.StringAttribute("requestID", e.RequestID()),
			trace.StringAttribute("code", e.Code()),
			trace.Int64Attribute("status", int64(e.StatusCode())),
		)
	}

	err = WrapEC2Error(err)
	tracehelpers.SetStatus(err, span)
	return err
}

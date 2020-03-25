package assign3

import (
	"context"
	"time"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"google.golang.org/grpc"
)

func Unassign(ctx context.Context, conn *grpc.ClientConn, taskID string) error {
	ctx, span := trace.StartSpan(ctx, "Unassign")
	defer span.End()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"taskID": taskID,
	})
	logger.G(ctx).Info()

	client := vpcapi.NewTitusAgentVPCServiceClient(conn)
	if taskID == "" {
		err := errors.New("Task ID must be specified")
		tracehelpers.SetStatus(err, span)
		return err
	}

	_, err := client.UnassignIPV3(ctx, &vpcapi.UnassignIPRequestV3{
		TaskId: taskID,
	})
	if err != nil {
		err = errors.Wrap(err, "Cannot unassign IPv3")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

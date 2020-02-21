package gc3

import (
	"context"
	"path/filepath"
	"time"

	"github.com/Netflix/titus-executor/logger"

	"github.com/Netflix/titus-executor/fslocker"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/Netflix/titus-executor/vpc/utilities"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

func GC(ctx context.Context, timeout time.Duration, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, conn *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "GC")
	defer span.End()

	optimisticTimeout := time.Duration(0)
	files, err := locker.ListFiles(utilities.GetTasksLockPath())
	if err != nil {
		err = errors.Wrap(err, "Cannot list files under tasks lock path")
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeUnknown,
			Message: err.Error(),
		})
		return err
	}

	runningTaskIDs := []string{}
	for idx := range files {
		taskID := files[idx].Name
		lockPath := filepath.Join(utilities.GetTasksLockPath(), taskID)
		lock, err := locker.ExclusiveLock(ctx, lockPath, &optimisticTimeout)
		if err == nil {
			_ = locker.RemovePath(lockPath)
			lock.Unlock()
		} else if err == unix.EWOULDBLOCK {
			runningTaskIDs = append(runningTaskIDs, taskID)
		} else {
			err = errors.Wrap(err, "Unexpected error while enumerating running tasks")
			span.SetStatus(trace.Status{
				Code:    trace.StatusCodeUnknown,
				Message: err.Error(),
			})
			return err
		}
	}

	logger.G(ctx).WithField("runningTasks", runningTaskIDs).Debug("Found running tasks")

	instanceIdentity, err := instanceIdentityProvider.GetIdentity(ctx)
	if err != nil {
		err = errors.Wrap(err, "Unable to get instance identity")
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeUnknown,
			Message: err.Error(),
		})
		return err
	}

	req := vpcapi.GCRequestV3{
		InstanceIdentity: instanceIdentity,
		RunningTaskIDs:   runningTaskIDs,
	}
	client := vpcapi.NewTitusAgentVPCServiceClient(conn)

	_, err = client.GCV3(ctx, &req)
	if err != nil {
		err = errors.Wrap(err, "Cannot call API to perform GC")
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeUnknown,
			Message: err.Error(),
		})
		return err
	}

	return nil
}

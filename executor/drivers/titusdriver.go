package titusdriver

import (
	"strconv"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/executor/runtime"
)

// TitusTaskState represents the current state of a task
type TitusTaskState uint32

// Possible Task states
const (
	Starting TitusTaskState = iota
	Running
	Finished // successfully
	Failed   // terminated by itself
	Killed   // stopped by request
	Lost     // terminated because of us
)

func (s TitusTaskState) String() string {
	switch s {
	case Starting:
		return "TASK_STARTING"
	case Running:
		return "TASK_RUNNING"
	case Finished:
		return "TASK_FINISHED"
	case Failed:
		return "TASK_FAILED"
	case Killed:
		return "TASK_KILLED"
	case Lost:
		return "TASK_LOST"
	default:
		return strconv.FormatUint(uint64(s), 10)
	}
}

// TitusDriver is the interface implemented by a generic Titus Executor Driver.
type TitusDriver interface {
	// ReportTitusTaskStatus is a callback function to notify the driver
	// of a change in task state.
	ReportTitusTaskStatus(taskID string, msg string, state TitusTaskState, details *runtime.Details)
}

// TitusExecutor is the interface implemented by a generic Titus executor.
type TitusExecutor interface {
	// SetTitusDriver sets callback driver to the executor to user
	SetTitusDriver(titusDriver TitusDriver)
	// Starts starts the executor. This is a blocking call.
	Start()
	// Stop stops the executor. This is a non-blocking call.
	// When Stop returns the executor may still be shutting down.
	Stop()
	// StartTask starts a new task
	StartTask(taskID string, titusInfo *titus.ContainerInfo, mem int64, cpu int64, disk uint64, hostPorts []uint16) error
	// StopTask stops an existing task
	StopTask(taskID string) error
}

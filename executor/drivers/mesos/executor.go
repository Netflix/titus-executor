package titusmesosdriver

import (
	"encoding/json"
	"sync"

	"github.com/Netflix/metrics-client-go/metrics"
	titusproto "github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/executor/drivers"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	protobuf "github.com/golang/protobuf/proto"
	"github.com/mesos/mesos-go/executor"
	"github.com/mesos/mesos-go/mesosproto"
	mesosUtil "github.com/mesos/mesos-go/mesosutil"
	log "github.com/sirupsen/logrus"
)

// titusMesosExecutor implements Mesos' Executor interface
type titusMesosExecutor struct {
	metrics       metrics.Reporter
	titusExecutor titusdriver.TitusExecutor

	// Keep the last registered driver for status updates
	mu          sync.Mutex
	mesosDriver executor.ExecutorDriver
}

// Registered registers a Mesos driver and starts the executor
func (e *titusMesosExecutor) Registered(mesosDriver executor.ExecutorDriver, execInfo *mesosproto.ExecutorInfo, fwinfo *mesosproto.FrameworkInfo, slaveInfo *mesosproto.SlaveInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// TODO(Andrew L): Log more stuff here
	log.Printf("Registering Mesos framework %+v", fwinfo)
	e.mesosDriver = mesosDriver
	e.titusExecutor.SetTitusDriver(e)
	go e.titusExecutor.Start()
}

// Reregistered registers a Mesos driver with a running executor
func (e *titusMesosExecutor) Reregistered(mesosDriver executor.ExecutorDriver, slaveInfo *mesosproto.SlaveInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()
	log.Printf("re-registered")
	e.mesosDriver = mesosDriver
	e.titusExecutor.SetTitusDriver(e)
}

// Disconnected stops a running executor
func (e *titusMesosExecutor) Disconnected(mesosExecDriver executor.ExecutorDriver) {
	log.Printf("disconnected")
	e.titusExecutor.Stop()
}

// LaunchTask starts a new task
func (e *titusMesosExecutor) LaunchTask(exec executor.ExecutorDriver, taskInfo *mesosproto.TaskInfo) {
	taskID := taskInfo.GetTaskId().GetValue()
	e.metrics.Counter("titus.executor.mesosLaunchTask", 1, nil)

	log.Printf("task %s : launch", taskID)

	// Get Titus task proto from Mesos data
	titusInfo := new(titusproto.ContainerInfo)
	if err := protobuf.Unmarshal(taskInfo.GetData(), titusInfo); err != nil {
		log.Printf("Failed to unmarshal protobuf data for task %s: %s", taskID, err)
		e.metrics.Counter("titus.executor.launchTaskFailed", 1, nil)
		e.ReportTitusTaskStatus(taskID, err.Error(), titusdriver.Lost, nil)
		return
	}
	// Get basic container dimensions from Mesos
	// TODO(Andrew L): We should move this info to the protobuf
	var mem, cpu int64
	var disk uint64
	var hostPorts []uint16
	for _, r := range taskInfo.GetResources() {
		if r.GetName() == "mem" {
			mem = int64(r.GetScalar().GetValue())
		} else if r.GetName() == "cpus" {
			cpu = int64(r.GetScalar().GetValue())
		} else if r.GetName() == "disk" {
			disk = uint64(r.GetScalar().GetValue())
		} else if r.GetName() == "ports" {
			for _, portRange := range r.GetRanges().GetRange() {
				for port := portRange.GetBegin(); port <= portRange.GetEnd(); port++ {
					hostPorts = append(hostPorts, uint16(port))
				}
			}
		}
	}

	if err := e.titusExecutor.StartTask(taskID, titusInfo, mem, cpu, disk, hostPorts); err != nil {
		log.Printf("Failed to start task %s: %s", taskID, err)
	}
}

// KillTask kills a running task
func (e *titusMesosExecutor) KillTask(exec executor.ExecutorDriver, taskID *mesosproto.TaskID) {
	if err := e.titusExecutor.StopTask(taskID.GetValue()); err != nil {
		log.Printf("Failed to stop task %s: %s", taskID.GetValue(), err)
	}
}

// FrameworkMessage sends a message from the framework to the executor
func (e *titusMesosExecutor) FrameworkMessage(exec executor.ExecutorDriver, msg string) {
	log.Printf("Received Mesos framework message %s", msg)
}

// Shutdown shuts the running executor down. All running tasks will be killed.
func (e *titusMesosExecutor) Shutdown(exec executor.ExecutorDriver) {
	log.Printf("Shutting down Mesos driver")
	e.titusExecutor.Stop()
}

// Error sends an error message from the framework to the executor.
func (e *titusMesosExecutor) Error(exec executor.ExecutorDriver, err string) {
	log.Printf("Received Mesos error %s", err)
}

// ReportTitusTaskStatus notifies Mesos of a change in task state.
func (e *titusMesosExecutor) ReportTitusTaskStatus(taskID string, msg string, state titusdriver.TitusTaskState, details *runtimeTypes.Details) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.mesosDriver == nil {
		log.Warnf("Attempted to report status for %s, but no mesos driver has been registered", taskID)
		return
	}

	log.Printf("task %s : details %#v", taskID, details)

	var dataBytes []byte
	if details != nil {
		dataBytes, _ = json.Marshal(details) // nolint: gas
	}

	mesosStatus := &mesosproto.TaskStatus{
		TaskId:  mesosUtil.NewTaskID(taskID),
		Message: protobuf.String(msg),
		State:   titusToMesosTaskState(state).Enum().Enum(),
		Data:    dataBytes,
	}

	if _, err := e.mesosDriver.SendStatusUpdate(mesosStatus); err != nil {
		e.metrics.Counter("titus.executor.mesosStatusSendError", 1, nil)
		log.Printf("Failed to send Mesos status update for task %s : %s", taskID, err)
		// TODO(Andrew L): Should we act on this failure? Presumably the Slave or Master may be
		// down so we can wait for their recovery action.
	}
}

func titusToMesosTaskState(titusState titusdriver.TitusTaskState) mesosproto.TaskState {
	var mesosState mesosproto.TaskState
	switch titusState {
	case titusdriver.Starting:
		mesosState = mesosproto.TaskState_TASK_STARTING
	case titusdriver.Running:
		mesosState = mesosproto.TaskState_TASK_RUNNING
	case titusdriver.Finished:
		mesosState = mesosproto.TaskState_TASK_FINISHED
	case titusdriver.Failed:
		mesosState = mesosproto.TaskState_TASK_FAILED
	case titusdriver.Killed:
		mesosState = mesosproto.TaskState_TASK_KILLED
	case titusdriver.Lost:
		mesosState = mesosproto.TaskState_TASK_LOST
	default:
		log.Printf("Unrecognized Titus task state %s", titusState.String())
		mesosState = mesosproto.TaskState_TASK_LOST
	}
	return mesosState
}

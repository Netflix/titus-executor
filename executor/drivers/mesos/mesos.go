package titusmesosdriver

import (
	"net"
	"os"
	"strconv"

	protobuf "github.com/golang/protobuf/proto"

	titusproto "github.com/Netflix/titus-executor/api/netflix/titus"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"

	"encoding/json"
	"sync"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/runner"
	mesosExecutor "github.com/mesos/mesos-go/executor"
	"github.com/mesos/mesos-go/mesosproto"
	mesosUtil "github.com/mesos/mesos-go/mesosutil"
	log "github.com/sirupsen/logrus"

	"time"
)

// TitusMesosDriver interacts withe the Mesos golang driver.
// Wraps the Titus Executor
type TitusMesosDriver struct {
	sync.Mutex
	metrics metrics.Reporter

	mesosDriver mesosExecutor.ExecutorDriver
	runner      *runner.Runner
}

const (
	mesosLibProcessIPKey   = "LIBPROCESS_IP"
	mesosLibProcessPortKey = "LIBPROCESS_PORT"
)

// New allocates a TitusMesosDriver, which includes an allocated Titus executor
// and an allocated Mesos driver.
func New(m metrics.Reporter, runner *runner.Runner) (*TitusMesosDriver, error) {
	var err error
	// Get required ENV vars that the Mesos slave should have set
	tmd := &TitusMesosDriver{
		runner:  runner,
		metrics: m,
	}

	driverCfg := mesosExecutor.DriverConfig{
		Executor: tmd,
	}

	addr := os.Getenv(mesosLibProcessIPKey)
	if addr != "" {
		driverCfg.BindingAddress = net.ParseIP(addr)
	}

	port := os.Getenv(mesosLibProcessPortKey)
	if port != "" {
		portNum, err := strconv.ParseUint(port, 10, 16) // nolint: gas
		if err != nil {
			log.Fatalf("Cannot parse variable %s with value %s", mesosLibProcessPortKey, port)
		}
		driverCfg.BindingPort = uint16(portNum)
	}

	log.Printf("Starting Mesos driver with Driverconfig: %+v", driverCfg)
	//mesosLibProcessIPKey, addr, mesosLibProcessPortKey, portNum)

	tmd.mesosDriver, err = mesosExecutor.NewMesosExecutorDriver(driverCfg)
	if err != nil {
		log.Printf("Unable to create ExecutorDriver : %s", err)
		return nil, err
	}
	return tmd, err
}

// Start starts the executor driver in the background
func (driver *TitusMesosDriver) Start() error {
	status, err := driver.mesosDriver.Start()
	if err != nil {
		log.Printf("Unable to start ExecutorDriver : %s", err)
		return err
	}
	log.Printf("Started Mesos executor driver with status : %s", status)
	go driver.taskStatusMonitor()
	go func() {
		<-driver.runner.StoppedChan
		time.Sleep(10 * time.Second)
		driver.mesosDriver.Stop()
	}()
	return nil
}

// Stop signals the Mesos Driver to stop its event loop.
// This operation does not block and the actual stopping happens asynchronously.
func (driver *TitusMesosDriver) Stop() error {
	status, err := driver.mesosDriver.Stop()
	log.Infof("Mesos driver stopped. Status: %s : %+v", status, err)
	return err
}

// Join waits for the Mesos driver to terminate.
// This is a blocking call.
func (driver *TitusMesosDriver) Join() error {
	status, err := driver.mesosDriver.Join()
	if err != nil {
		log.Printf("Unable to join on Mesos driver with status %s: %s", status, err)
		return err
	}

	driver.runner.Kill()
	<-driver.runner.StoppedChan

	log.Printf("Joined on Mesos driver with status %s : %s", status, err)
	return nil
}

// Registered registers a Mesos driver and starts the executor
func (e *TitusMesosDriver) Registered(mesosDriver mesosExecutor.ExecutorDriver, execInfo *mesosproto.ExecutorInfo, fwinfo *mesosproto.FrameworkInfo, slaveInfo *mesosproto.SlaveInfo) {
	e.Lock()
	defer e.Unlock()
	// TODO(Andrew L): Log more stuff here
	log.Printf("Registering Mesos framework %+v", fwinfo)
	e.mesosDriver = mesosDriver

}

// Reregistered registers a Mesos driver with a running executor
func (e *TitusMesosDriver) Reregistered(mesosDriver mesosExecutor.ExecutorDriver, slaveInfo *mesosproto.SlaveInfo) {
	e.Lock()
	defer e.Unlock()
	log.Printf("re-registered")
	e.mesosDriver = mesosDriver
}

// Disconnected stops a running executor
func (e *TitusMesosDriver) Disconnected(mesosExecDriver mesosExecutor.ExecutorDriver) {
	log.Printf("disconnected")
	e.mesosDriver.Stop()
}

// LaunchTask starts a new task
func (e *TitusMesosDriver) LaunchTask(exec mesosExecutor.ExecutorDriver, taskInfo *mesosproto.TaskInfo) {
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

	if err := e.runner.StartTask(taskID, titusInfo, mem, cpu, disk); err != nil {
		log.Printf("Failed to start task %s: %s", taskID, err)
	}
}

// KillTask kills a running task
func (e *TitusMesosDriver) KillTask(exec mesosExecutor.ExecutorDriver, taskID *mesosproto.TaskID) {
	e.runner.Kill()
}

// FrameworkMessage sends a message from the framework to the executor
func (e *TitusMesosDriver) FrameworkMessage(exec mesosExecutor.ExecutorDriver, msg string) {
	log.Printf("Received Mesos framework message %s", msg)
}

// Shutdown shuts the running executor down. All running tasks will be killed.
func (e *TitusMesosDriver) Shutdown(exec mesosExecutor.ExecutorDriver) {
	log.Printf("Shutting down Mesos driver")
	e.runner.Kill()
}

// Error sends an error message from the framework to the executor.
func (e *TitusMesosDriver) Error(exec mesosExecutor.ExecutorDriver, err string) {
	log.Printf("Received Mesos error %s", err)
}

func (e *TitusMesosDriver) taskStatusMonitor() {
	for update := range e.runner.UpdatesChan {
		e.handleUpdate(update)
	}
}

func (e *TitusMesosDriver) handleUpdate(update runner.Update) {
	e.Lock()
	defer e.Unlock()
	if e.mesosDriver == nil {
		log.Error("Attempted to report status for %s, but no mesos driver has been registered", update.TaskID)
		return
	}
	log.Printf("task %s : details %#v", update.TaskID, update.Details)
	var dataBytes []byte
	if update.Details != nil {
		dataBytes, _ = json.Marshal(update.Details) // nolint: gas
	}

	mesosStatus := &mesosproto.TaskStatus{
		TaskId:  mesosUtil.NewTaskID(update.TaskID),
		Message: protobuf.String(update.Mesg),
		State:   titusToMesosTaskState(update.State).Enum().Enum(),
		Data:    dataBytes,
	}

	if _, err := e.mesosDriver.SendStatusUpdate(mesosStatus); err != nil {
		e.metrics.Counter("titus.executor.mesosStatusSendError", 1, nil)
		log.Printf("Failed to send Mesos status update for task %s : %s", update.TaskID, err)
		// TODO(Andrew L): Should we act on this failure? Presumably the Slave or Master may be
		// down so we can wait for their recovery action.
	}
}

// ReportTitusTaskStatus notifies Mesos of a change in task state.
func (e *TitusMesosDriver) ReportTitusTaskStatus(taskID string, msg string, state titusdriver.TitusTaskState, details *runtimeTypes.Details) {
	e.Lock()
	defer e.Unlock()

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

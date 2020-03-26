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
	titusdriver "github.com/Netflix/titus-executor/executor/drivers"
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
		portNum, err := strconv.ParseUint(port, 10, 16) // nolint: gosec
		if err != nil {
			log.Fatalf("Cannot parse variable %s with value %s", mesosLibProcessPortKey, port)
		}
		driverCfg.BindingPort = uint16(portNum)
	}

	log.Printf("Starting Mesos driver with Driverconfig: %+v", driverCfg)
	//mesosLibProcessIPKey, addr, mesosLibProcessPortKey, portNum)

	var err error
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
		if _, err2 := driver.mesosDriver.Stop(); err2 != nil {
			log.Error("Could not stop mesos driver: ", err2)
		}

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
func (driver *TitusMesosDriver) Registered(mesosDriver mesosExecutor.ExecutorDriver, execInfo *mesosproto.ExecutorInfo, fwinfo *mesosproto.FrameworkInfo, slaveInfo *mesosproto.SlaveInfo) {
	driver.Lock()
	defer driver.Unlock()
	// TODO(Andrew L): Log more stuff here
	log.Printf("Registering Mesos framework %+v", fwinfo)
	driver.mesosDriver = mesosDriver

}

// Reregistered registers a Mesos driver with a running executor
func (driver *TitusMesosDriver) Reregistered(mesosDriver mesosExecutor.ExecutorDriver, slaveInfo *mesosproto.SlaveInfo) {
	driver.Lock()
	defer driver.Unlock()
	log.Printf("re-registered")
	driver.mesosDriver = mesosDriver
}

// Disconnected stops a running executor
func (driver *TitusMesosDriver) Disconnected(mesosExecDriver mesosExecutor.ExecutorDriver) {
	log.Printf("disconnected")
	if _, err2 := driver.mesosDriver.Stop(); err2 != nil {
		log.Error("Could not stop mesos driver: ", err2)
	}
}

// LaunchTask starts a new task
func (driver *TitusMesosDriver) LaunchTask(exec mesosExecutor.ExecutorDriver, taskInfo *mesosproto.TaskInfo) {
	taskID := taskInfo.GetTaskId().GetValue()
	driver.metrics.Counter("titus.executor.mesosLaunchTask", 1, nil)

	log.Printf("task %s : launch", taskID)

	// Get Titus task proto from Mesos data
	titusInfo := new(titusproto.ContainerInfo)
	if err := protobuf.Unmarshal(taskInfo.GetData(), titusInfo); err != nil {
		log.Printf("Failed to unmarshal protobuf data for task %s: %s", taskID, err)
		driver.metrics.Counter("titus.executor.launchTaskFailed", 1, nil)
		driver.ReportTitusTaskStatus(taskID, err.Error(), titusdriver.Lost, nil)
		return
	}
	// Get basic container dimensions from Mesos
	// TODO(Andrew L): We should move this info to the protobuf
	var mem, cpu, gpu int64
	var disk uint64
	for _, r := range taskInfo.GetResources() {
		if r.GetName() == "mem" {
			mem = int64(r.GetScalar().GetValue())
		} else if r.GetName() == "cpus" {
			cpu = int64(r.GetScalar().GetValue())
		} else if r.GetName() == "disk" {
			disk = uint64(r.GetScalar().GetValue())
		} else if r.GetName() == "gpu" {
			gpu = int64(r.GetScalar().GetValue())
		}
	}

	if err := driver.runner.StartTask(taskID, titusInfo, mem, cpu, gpu, disk); err != nil {
		log.Printf("Failed to start task %s: %s", taskID, err)
	}
}

// KillTask kills a running task
func (driver *TitusMesosDriver) KillTask(exec mesosExecutor.ExecutorDriver, taskID *mesosproto.TaskID) {
	time.AfterFunc(time.Hour, func() {
		log.Error("Executor is performing emergency termination after task kill")
		time.Sleep(10 * time.Second)
		os.Exit(1)
	})
	driver.runner.Kill()
}

// FrameworkMessage sends a message from the framework to the executor
func (driver *TitusMesosDriver) FrameworkMessage(exec mesosExecutor.ExecutorDriver, msg string) {
	log.Printf("Received Mesos framework message %s", msg)
}

// Shutdown shuts the running executor down. All running tasks will be killed.
func (driver *TitusMesosDriver) Shutdown(exec mesosExecutor.ExecutorDriver) {
	log.Printf("Shutting down Mesos driver")
	time.AfterFunc(time.Hour, func() {
		log.Error("Executor is performing emergency termination after shutdown")
		time.Sleep(10 * time.Second)
		os.Exit(1)
	})
	driver.runner.Kill()
}

// Error sends an error message from the framework to the executor.
func (driver *TitusMesosDriver) Error(exec mesosExecutor.ExecutorDriver, err string) {
	log.Printf("Received Mesos error %s", err)
}

func (driver *TitusMesosDriver) taskStatusMonitor() {
	for update := range driver.runner.UpdatesChan {
		driver.handleUpdate(update)
	}
}

func (driver *TitusMesosDriver) handleUpdate(update runner.Update) {
	driver.Lock()
	defer driver.Unlock()
	if driver.mesosDriver == nil {
		log.Errorf("Attempted to report status for %s, but no mesos driver has been registered", update.TaskID)
		return
	}
	log.Printf("Updating task %s : details %#v", update.TaskID, update.Details)
	var dataBytes []byte
	if update.Details != nil {
		dataBytes, _ = json.Marshal(update.Details) // nolint: gosec
	}

	mesosStatus := &mesosproto.TaskStatus{
		TaskId:  mesosUtil.NewTaskID(update.TaskID),
		Message: protobuf.String(update.Mesg),
		State:   titusToMesosTaskState(update.State).Enum().Enum(),
		Data:    dataBytes,
	}

	if _, err := driver.mesosDriver.SendStatusUpdate(mesosStatus); err != nil {
		driver.metrics.Counter("titus.executor.mesosStatusSendError", 1, nil)
		log.Printf("Failed to send Mesos status update for task %s : %s", update.TaskID, err)
		// TODO(Andrew L): Should we act on this failure? Presumably the Slave or Master may be
		// down so we can wait for their recovery action.
	}
}

// ReportTitusTaskStatus notifies Mesos of a change in task state.
func (driver *TitusMesosDriver) ReportTitusTaskStatus(taskID string, msg string, state titusdriver.TitusTaskState, details *runtimeTypes.Details) {
	driver.Lock()
	defer driver.Unlock()

	if driver.mesosDriver == nil {
		log.Warnf("Attempted to report status for %s, but no mesos driver has been registered", taskID)
		return
	}

	log.Printf("task %s : details %#v", taskID, details)

	var dataBytes []byte
	if details != nil {
		dataBytes, _ = json.Marshal(details) // nolint: gosec
	}

	mesosStatus := &mesosproto.TaskStatus{
		TaskId:  mesosUtil.NewTaskID(taskID),
		Message: protobuf.String(msg),
		State:   titusToMesosTaskState(state).Enum().Enum(),
		Data:    dataBytes,
	}

	if _, err := driver.mesosDriver.SendStatusUpdate(mesosStatus); err != nil {
		driver.metrics.Counter("titus.executor.mesosStatusSendError", 1, nil)
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

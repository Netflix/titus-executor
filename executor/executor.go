package executor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/metatron"
	"github.com/Netflix/titus-executor/executor/runtime"
	"github.com/Netflix/titus-executor/filesystems"
	launchguardClient "github.com/Netflix/titus-executor/launchguard/client"
	launchguardCore "github.com/Netflix/titus-executor/launchguard/core"
	"github.com/Netflix/titus-executor/models"
	"github.com/Netflix/titus-executor/uploader"
	log "github.com/sirupsen/logrus"
)

const shutdownTimeout = time.Hour
const killTimeout = 5 * time.Minute

type update struct {
	TaskID  string
	State   titusdriver.TitusTaskState
	Mesg    string
	Details *runtime.Details
	ce      launchguardCore.CleanUpEvent
}

func (u update) withDetails(details *runtime.Details) update {
	u.Details = details
	return u
}
func (u update) withCleanUpEvent(ce launchguardCore.CleanUpEvent) update {
	u.ce = ce
	return u
}
func newUpdate(taskID string, state titusdriver.TitusTaskState, mesg string) update {
	return update{
		TaskID: taskID,
		State:  state,
		Mesg:   mesg,
	}
}

type containerState struct {
	sync.Mutex
	*runtime.Container
	isKilled bool
	watcher  *filesystems.Watcher

	logEntry *log.Entry
	/* Don't refer directly to these members */
	_ctx    context.Context
	_cancel context.CancelFunc
}

func (c *containerState) context() context.Context {
	return c._ctx
}

func (c *containerState) cancel() {
	c._cancel()
}

// Executor maintains in memory state for the executor
type Executor struct {
	metrics      metrics.Reporter
	titusDriver  titusdriver.TitusDriver
	runtime      runtime.Runtime
	logUploaders *uploader.Uploaders

	sync.RWMutex
	tasks      map[string]*containerState
	taskStates map[string]titusdriver.TitusTaskState

	launchGuard *launchguardClient.LaunchGuardClient

	update       chan update
	cancel       context.CancelFunc
	ctx          context.Context
	shutdownDone chan bool

	serveMux              *http.ServeMux
	ephemeralHTTPListener net.Listener
}

// RuntimeProvider is a factory function for runtime implementations. It is called only once by WithRuntime
type RuntimeProvider func(context.Context) (runtime.Runtime, error)

// New constructs a new Executor object with the default (docker) runtime
func New(m metrics.Reporter, logUploaders *uploader.Uploaders) (*Executor, error) {
	dockerRuntime := func(ctx context.Context) (runtime.Runtime, error) {
		return runtime.NewDockerRuntime(ctx, m)
	}
	return WithRuntime(m, dockerRuntime, logUploaders)
}

// WithRuntime builds an Executor using the provided Runtime factory func
func WithRuntime(m metrics.Reporter, rp RuntimeProvider, logUploaders *uploader.Uploaders) (*Executor, error) {
	if config.MetatronEnabled() {
		if err := metatron.InitMetatronTruststore(); err != nil {
			return nil, fmt.Errorf("Failed to initialize Metatron trust store: %s", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background()) // nolint: vet
	r, err := rp(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	lgc, err := launchguardClient.NewLaunchGuardClient(m, "http://localhost:8006")
	if err != nil {
		return nil, err // nolint: vet
	}
	exec := &Executor{
		metrics:      m,
		runtime:      r,
		logUploaders: logUploaders,
		tasks:        make(map[string]*containerState),
		taskStates:   make(map[string]titusdriver.TitusTaskState),
		update:       make(chan update),
		ctx:          ctx,
		cancel:       cancel,
		shutdownDone: make(chan bool),
		launchGuard:  lgc,
	}
	exec.setupServeMux()
	exec.setupEphemeralHTTPServer()
	return exec, nil
}

// SetTitusDriver sets the callback driver that the executor will use
// to notify the driver of task changes.
func (e *Executor) SetTitusDriver(driver titusdriver.TitusDriver) {
	e.titusDriver = driver
}

// deleteTaskFromMap removes a task ID from the executor's
// in memory list of tasks. It is an idempotent function, so it's safe to call it _no matter what_
// See: The delete built-in function deletes the element with the specified key (m[key]) from the map.
// If m is nil or there is no such element, delete is a no-op.
func (e *Executor) deleteTaskFromMap(taskID string) {
	e.Lock()
	defer e.Unlock()
	delete(e.tasks, taskID)
	delete(e.taskStates, taskID)
}

func (e *Executor) runCheck(taskID string) bool {
	e.RLock()
	c, ok := e.tasks[taskID]
	e.RUnlock()
	if !ok {
		log.WithField("taskID", taskID).Info("unable to find task to check in executor map")
		return true
	}

	// Warning: we don't hold a lock on the container anymore, there may be concurrent modifications to it
	status, err := e.runtime.Status(c.Container)
	if err != nil {
		log.Errorf("Status result error %v", err)
	}

	switch status {
	case runtime.StatusRunning:
		// no need to update the status if task is running
		c.logEntry.Debug("running")
		return false
	case runtime.StatusFinished:
		c.logEntry.Info("finished")
		e.update <- newUpdate(taskID, titusdriver.Finished, "finished")
		return true
	case runtime.StatusFailed:
		c.logEntry.Info("failed")
		e.update <- newUpdate(taskID, titusdriver.Failed, err.Error())
		return true
	default:
		c.logEntry.Error("status unknown (lost): ", err)
		e.update <- newUpdate(taskID, titusdriver.Lost, err.Error())
		return true
	}
}

func (e *Executor) monitorTask(c *containerState) {
	ticks := time.NewTicker(config.StatusCheckFrequency())
	defer ticks.Stop()
	// Probably should also look at the container's context?
	for range ticks.C {
		if e.runCheck(c.Container.TaskID) {
			c.logEntry.Info("Ending monitoring for task")
			return
		}
	}
}

func isRunning(state titusdriver.TitusTaskState) bool {
	return state == titusdriver.Starting || state == titusdriver.Running
}

// GetNumTasks returns the current number of active (i.e., starting, running, shutting down) tasks
func (e *Executor) GetNumTasks() int {
	e.Lock()
	defer e.Unlock()
	return len(e.tasks)
}

// Start is a blocking call that runs the executor
func (e *Executor) Start() {
	defer e.cancel()
	for {
		select {
		case <-e.ctx.Done():
			var tasksToKill []update
			e.Lock()
			for taskID := range e.tasks {
				tasksToKill = append(tasksToKill, newUpdate(taskID, titusdriver.Killed, "Executor shutdown"))
			}
			e.Unlock()
			for i := range tasksToKill {
				e.killContainer(tasksToKill[i])
			}
			// When told to die we expect the caller is waiting for the result.
			close(e.shutdownDone)
			return
		case update := <-e.update: // nolint: vetshadow
			log.Printf("received value from channel %+v", update)
			if isRunning(update.State) {
				e.titusDriver.ReportTitusTaskStatus(update.TaskID, update.Mesg, update.State, update.Details)
				le := log.WithField("taskID", update.TaskID).WithField("state", update.State)
				if update.Details != nil {
					le = le.WithField("details", update.Details)
				}
				le.Info("executor reported status")
			} else {
				go e.killContainer(update)
			}
			e.Lock()
			e.taskStates[update.TaskID] = update.State
			e.Unlock()
		}
	}
}

// setupMetatron returns a Docker formatted string bind mount for a container for a directory that will contain
// TODO(fabio): create a type for Binds
func (e *Executor) setupMetatron(c *runtime.Container) (*metatron.CredentialsConfig, error) {
	if config.DevWorkspace().MockMetatronCreds {
		// Make up some creds for local testing
		testAppMetadata := "type=titus&version=1&app=myApp&stack=myStack&imageName=myImage&imageVersion=latest&entry=myEntryPoint&t=1481328000"
		testAppSignature := "keyID=10&sAlg=SHA256withRSAandMGF1&sig=RGVjb2RlIGJhc2U2NCBzdHJpbmdzIChiYXNlNjQgc3RyaW5nIGxvb2tzIGxpa2UgWVRNME5ab21JekkyT1RzbUl6TTBOVHVlWVE9PSkNCkRlY29kZSBhIGJhc2U2NCBlbmNvZGVkIGZpbGUgKGZvciBleGFtcGxlIElDTyBmaWxlcyBvciBmaWxlcyB"
		c.TitusInfo.MetatronCreds = &titus.ContainerInfo_MetatronCreds{
			AppMetadata: &testAppMetadata,
			MetadataSig: &testAppSignature,
		}
	}

	if c.TitusInfo.GetMetatronCreds() == nil {
		return nil, nil
	}

	envMap := c.TitusInfo.GetUserProvidedEnv()
	if envMap == nil {
		envMap = make(map[string]string)
	}

	titusMetadata := metatron.TitusMetadata{
		App:          c.TitusInfo.GetAppName(),
		Stack:        c.TitusInfo.GetJobGroupStack(),
		ImageName:    c.TitusInfo.GetImageName(),
		ImageVersion: c.TitusInfo.GetVersion(),
		Entrypoint:   c.TitusInfo.GetEntrypointStr(),
		Env:          envMap,
		TaskID:       c.TaskID,
		LaunchTime:   (time.Now().UnixNano() / int64(time.Millisecond)),
	}

	metatronConfig, err := metatron.GetPassports(
		c.TitusInfo.MetatronCreds.AppMetadata,
		c.TitusInfo.MetatronCreds.MetadataSig,
		c.TaskID,
		titusMetadata)
	if err != nil {
		log.Errorf("Get Metatron Passport credentials failed: %s", err)
		return nil, err
	}
	log.Infof("Retrieved Metatron Passport credentials for %s", c.TaskID)
	return metatronConfig, nil
}

// killContainer is a bit of a misnomer. This is more of the:
// if the container is running, kill it, but if it shut down gracefully, please clean it up.
func (e *Executor) killContainer(updateInfo update) { // nolint: gocyclo
	var (
		cleanupErrs []error
		taskID      = updateInfo.TaskID
	)

	if updateInfo.ce != nil {
		defer updateInfo.ce.Done()
	}

	e.Lock()
	c, exists := e.tasks[taskID]
	if exists {
		// This preserves the entry in task status. I don't know if this is intentional?
		delete(e.tasks, taskID)
	}
	e.Unlock()

	if !exists {
		log.Infof("task %s is not being tracked anymore (being or already killed): ", taskID)
		return
	}

	// Once we do this, there's no turning back. In some period of time, the watcher will begin to terminate, and it'll be over shortly.
	c.cancel()

	c.Lock()
	defer c.Unlock()

	killStartTime := time.Now()
	c.isKilled = true
	if err := e.runtime.Kill(c.Container); err != nil {
		// TODO(Andrew L): There may be leaked resources that are not being
		// accounted for. Consider forceful cleanup or tracking leaked resources.
		log.Errorf("Failed to fully complete primary kill actions: %v", err)
		cleanupErrs = append(cleanupErrs, err)
	}

	// Release the launch guard here if we're blocking concurrent task
	// launches while killing the container. We only block
	// concurrent launches to avoid a race condition introduced
	// by the Titus master releasing resources prior to the agent releasing them.
	// Release the launchGuard after the first phase of cleanup.
	if updateInfo.ce != nil {
		log.WithField("taskID", updateInfo.TaskID).Info("Unsetting launchguard")
		updateInfo.ce.Done()
	} else {
		log.WithField("taskID", updateInfo.TaskID).Info("No launchguard to unset")
	}

	if c.watcher != nil {
		if err := c.watcher.Stop(); err != nil {
			log.Errorf("Error while shutting down watcher for %s : %v", c.TaskID, err)
			cleanupErrs = append(cleanupErrs, err)
		}
	}

	if err := e.runtime.Cleanup(c.Container); err != nil {
		log.Errorf("Cleanup for %s failed : %v", c.TaskID, err)
		cleanupErrs = append(cleanupErrs, err)
	}

	e.metrics.Counter("titus.executor.taskCleanupDone", 1, nil)

	if updateInfo.State == titusdriver.Finished && len(cleanupErrs) > 0 {
		// TODO(Andrew L): There may be leaked resources that are not being
		// accounted for. Consider forceful cleanup or tracking leaked resources.
		// If the task finished successfully, include any info about cleanup errors
		updateInfo.Mesg = fmt.Sprintf("%+v", cleanupErrs)
	}
	e.titusDriver.ReportTitusTaskStatus(updateInfo.TaskID, updateInfo.Mesg, updateInfo.State, updateInfo.Details)
	e.metrics.Timer("titus.executor.containerCleanupTime", time.Since(killStartTime), c.ImageTagForMetrics())
	log.Printf("executor done container kill : task %s", taskID)
}

// Stop is a blocking call that stops the executor and kills all running tasks.
func (e *Executor) Stop() {
	e.cancel()
	// Wait until the executor has shutdown
	select {
	case <-e.shutdownDone:
		log.Printf("Executor shutdown complete")
	case <-time.After(shutdownTimeout):
		log.Printf("Executor shutdown timed out after %s", shutdownTimeout.String())
	}
}

// StartTask starts a new task
// TODO(fabio): pass in a Resources struct
func (e *Executor) StartTask(taskID string, titusInfo *titus.ContainerInfo, mem int64, cpu int64, disk uint64, hostPorts []uint16) error {
	startTime := time.Now()
	labels := map[string]string{
		models.ExecutorPidLabel: fmt.Sprintf("%d", os.Getpid()),
		models.TaskIDLabel:      taskID,
	}
	if e.ephemeralHTTPListener != nil {
		labels[models.ExecutorHTTPListenerAddressLabel] = e.ephemeralHTTPListener.Addr().String()
	}
	if len(titusInfo.GetIamProfile()) > 0 {
		labels["ec2.iam.role"] = titusInfo.GetIamProfile()
	}

	containerCtx, containerCancel := context.WithCancel(e.ctx)

	c := &containerState{
		Container: runtime.NewContainer(taskID, titusInfo,
			&runtime.Resources{
				Mem:       mem,
				CPU:       cpu,
				Disk:      disk,
				HostPorts: hostPorts,
			}, labels,
		),
		_ctx:     containerCtx,
		_cancel:  containerCancel,
		logEntry: log.WithField("taskID", taskID),
	}
	e.Lock()
	e.tasks[taskID] = c
	e.Unlock()

	go e.startContainer(c, startTime)

	return nil
}

func (e *Executor) startContainer(c *containerState, startTime time.Time) { // nolint: gocyclo
	var (
		bindMounts = []string{}
		err        error
	)

	// the container entry can be deletes in killContainer
	if c.context().Err() != nil {
		c.logEntry.Errorf("Task was killed before its launch initiated")
		e.deleteTaskFromMap(c.Container.TaskID)
		return
	}

	e.update <- newUpdate(c.Container.TaskID, titusdriver.Starting, "waiting_on_launchguard")

	// Wait until the launchGuard is released.
	// TODO(Andrew L): We only block concurrent launches to avoid a race condition introduced
	// by the Titus master releasing resources prior to the agent releasing them.
	le := e.launchGuard.NewLaunchEvent(c.context(), "default")
	select {
	case <-le.Launch():
		c.logEntry.Info("Launch not blocked on on launchGuard")
	default:
		c.logEntry.Info("Launch waiting on launchGuard")
		<-le.Launch()
		c.logEntry.Info("No longer waiting on launchGuard")
	}

	// Send another update to indicate that we've gotten passed launchguard.
	e.update <- newUpdate(c.Container.TaskID, titusdriver.Starting, "creating_metatron")

	c.Lock()
	defer c.Unlock()

	// Only request Metatron credentials once we have Metatron deps installed on the box.
	// Otherwise, the Metatron setup will always fail.
	if config.MetatronEnabled() {
		c.MetatronConfig, err = e.setupMetatron(c.Container) // nolint: vetshadow
		defer func() {
			// Remove any Metatron credential stored for the task since they will
			// get copied into the container.
			if err = metatron.RemovePassports(c.Container.TaskID); err != nil {
				log.Errorf("Failed to remove Metatron passport dir: %v", err)
			} else {
				log.Infoln("Removed Metadata host passport dir")
			}
		}()
		if err != nil {
			// We are expecting executor container cleanup to remove
			// any files created during the process
			c.logEntry.Errorf("Failed to acquire Metatron certificates: %s", err)
			e.update <- newUpdate(c.Container.TaskID, titusdriver.Lost, err.Error())
			return
		}
	}
	e.update <- newUpdate(c.Container.TaskID, titusdriver.Starting, "creating")

	// When Create() returns the host may have been modified to create storage and pull the image.
	// These steps may or may not have completed depending on if/where a failure occurred.
	err = e.runtime.Prepare(c.context(), c.Container, bindMounts)
	if err != nil {
		e.metrics.Counter("titus.executor.launchTaskFailed", 1, nil)
		c.logEntry.Errorf("task %s: failed to create container %s", c.Container.TaskID, err)
		// Treat registry pull errors as LOST and non-existent images as FAILED.
		switch err.(type) {
		case *runtime.RegistryImageNotFoundError, *runtime.InvalidSecurityGroupError, *runtime.BadEntryPointError:
			c.logEntry.Errorf("Returning TASK_FAILED for task %s : %v", c.Container.TaskID, err)
			e.update <- newUpdate(c.Container.TaskID, titusdriver.Failed, err.Error())
		default:
			c.logEntry.Errorf("Returning TASK_LOST for task %s : %v", c.Container.TaskID, err)
			e.update <- newUpdate(c.Container.TaskID, titusdriver.Lost, err.Error())
		}
		return
	}
	e.update <- newUpdate(c.Container.TaskID, titusdriver.Starting, "starting")

	if logDir, err := e.runtime.Start(c.context(), c.Container); err != nil { // nolint: vetshadow
		e.metrics.Counter("titus.executor.launchTaskFailed", 1, nil)
		c.logEntry.Printf("task %s : start container %s", c.Container.TaskID, err)

		switch err.(type) {
		case *runtime.BadEntryPointError:
			c.logEntry.Printf("Returning TaskState_TASK_FAILED for task %s : %v", c.Container.TaskID, err)
			e.update <- newUpdate(c.Container.TaskID, titusdriver.Failed, err.Error())
		default:
			c.logEntry.Printf("Returning TASK_LOST for task %s : %v", c.Container.TaskID, err)
			e.update <- newUpdate(c.Container.TaskID, titusdriver.Lost, err.Error())
		}
		return
	} else if logDir != "" {
		c.logEntry.Info("Starting external logger")
		// Error handling is handled in the external Logger setup
		if e.maybeSetupExternalLogger(c, logDir) != nil {
			return
		}
	} else {
		c.logEntry.Info("Not starting external logger")
	}

	if err != nil {
		return
	}
	// TODO(fabio): Start should return Details
	details, err := e.runtime.Details(c.Container)
	if err != nil {
		log.Errorf("Error fetching details for %s : %v", c.TaskID, err)
	}
	e.metrics.Counter("titus.executor.taskLaunched", 1, nil)
	select {
	case e.update <- newUpdate(c.Container.TaskID, titusdriver.Running, "running").withDetails(details):
	case <-e.ctx.Done():
		log.Errorf("startContainer for task %s got canceled", c.TaskID)
		return
	}

	// We do this to run any deferred bits, rather than running monitorTask in the same goroutine
	go e.monitorTask(c)

	// report metrics for startup time, docker image size
	e.metrics.Timer("titus.executor.containerStartTime", time.Since(startTime), c.ImageTagForMetrics())
}

func (e *Executor) maybeSetupExternalLogger(c *containerState, logDir string) error {
	var err error

	uploadDir := c.UploadDir("logs")
	uploadRegex := c.TitusInfo.GetLogUploadRegexp()
	c.watcher, err = filesystems.NewWatcher(e.metrics, logDir, uploadDir, uploadRegex, e.logUploaders)
	if err != nil {
		goto error
	}

	err = c.watcher.Watch(c.context())
	if err != nil {
		goto error
	}

	return nil

error:
	c.logEntry.Error("Unable to setup logging for container: ", err)
	_ = e.runtime.Kill(c.Container) // nolint: gas
	e.update <- newUpdate(c.Container.TaskID, titusdriver.Lost, err.Error())
	go func() {
		_ = e.runtime.Cleanup(c.Container) // nolint: gas
	}()
	return err
}

// StopTask stops a running task
func (e *Executor) StopTask(taskID string) error {
	log.Printf("task %s : kill", taskID)
	e.Lock()
	_, exists := e.tasks[taskID]
	e.Unlock()

	if !exists {
		log.WithField("taskID", taskID).Info("No such task")
		return nil
	}

	// Enable launch guard to prevent subsequent launch requests
	log.Printf("Setting launchGuard while stopping task %s", taskID)
	ctx, cancel := context.WithTimeout(e.ctx, killTimeout)
	_ = cancel
	ce := e.launchGuard.NewRealCleanUpEvent(ctx, "default")

	select {
	// After we put this message on the channel it'll get read in the main executor loop,
	// and the main executor loop will read it and mark the container as killed, and subsequently
	// call the kill function
	case e.update <- newUpdate(taskID, titusdriver.Killed, "mesos").withCleanUpEvent(ce):
	case <-e.ctx.Done():
		return fmt.Errorf("Stop for task %s canceled", taskID)
	}

	return nil
}

// ContainerID returns a container runtime specific ID for a task
func (e *Executor) ContainerID(taskID string) string {
	e.Lock()
	defer e.Unlock()

	if c := e.tasks[taskID]; c != nil {
		return c.Container.ID
	}
	return ""
}

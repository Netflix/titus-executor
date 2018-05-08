package runner

import (
	"context"
	"sync"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/uploader"

	launchguardClient "github.com/Netflix/titus-executor/launchguard/client"
	launchguardCore "github.com/Netflix/titus-executor/launchguard/core"

	"github.com/Netflix/titus-executor/executor/runtime"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"

	"errors"
	"fmt"
	"os"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/metatron"
	"github.com/Netflix/titus-executor/filesystems"
	"github.com/Netflix/titus-executor/models"
	"github.com/sirupsen/logrus"
)

// WaitingOnLaunchguardMessage is the status message we send to the master while we wait for launchguard
const WaitingOnLaunchguardMessage = "waiting_on_launchguard"
const waitForTaskTimeout = 5 * time.Minute

var (
	errorRunnerAlreadyStarted = errors.New("Runner already started task or not available")
	errorTaskWaitTimeout      = errors.New("Runner timed out waiting for task")
)

// Config is runner config

type task struct {
	taskID    string
	titusInfo *titus.ContainerInfo
	mem       int64
	cpu       int64
	disk      uint64
}

// Runner maintains in memory state for the task runner
type Runner struct { // nolint: maligned
	// const:
	metrics     metrics.Reporter
	runtime     runtimeTypes.Runtime
	launchGuard *launchguardClient.LaunchGuardClient
	config      config.Config
	logger      *logrus.Entry

	container *runtimeTypes.Container
	watcher   *filesystems.Watcher

	// TODO: Remove
	logUploaders *uploader.Uploaders

	sync.RWMutex
	err      error
	taskChan chan task
	// Close this channel to start killing the container
	killOnce    sync.Once
	killChan    chan struct{}
	StoppedChan chan struct{}
	UpdatesChan chan Update
	lastStatus  titusdriver.TitusTaskState
}

// RuntimeProvider is a factory function for runtime implementations. It is called only once by WithRuntime
type RuntimeProvider func(context.Context, config.Config) (runtimeTypes.Runtime, error)

// New constructs a new Executor object with the default (docker) runtime
func New(ctx context.Context, m metrics.Reporter, logUploaders *uploader.Uploaders, cfg config.Config, dockerCfg docker.Config) (*Runner, error) {
	dockerRuntime := func(ctx context.Context, cfg config.Config) (runtimeTypes.Runtime, error) {
		return docker.NewDockerRuntime(ctx, m, dockerCfg, cfg)
	}
	return WithRuntime(ctx, m, dockerRuntime, logUploaders, cfg)
}

// WithRuntime builds an Executor using the provided Runtime factory func
func WithRuntime(ctx context.Context, m metrics.Reporter, rp RuntimeProvider, logUploaders *uploader.Uploaders, cfg config.Config) (*Runner, error) {
	lgc, err := launchguardClient.NewLaunchGuardClient(m, "http://localhost:8006")
	if err != nil {
		return nil, err // nolint: vet
	}

	runner := &Runner{
		logger:       logrus.NewEntry(logrus.StandardLogger()),
		metrics:      m,
		logUploaders: logUploaders,
		launchGuard:  lgc,
		config:       cfg,
		taskChan:     make(chan task, 1),
		killChan:     make(chan struct{}),
		UpdatesChan:  make(chan Update, 10),
		StoppedChan:  make(chan struct{}),
	}
	setupCh := make(chan error)
	go runner.startRunner(ctx, setupCh, rp)
	go func() {
		<-ctx.Done()
		// Kill the running container if there is one, shut it down
		runner.Kill()
	}()
	err = <-setupCh
	if err != nil {
		return nil, err
	}

	return runner, nil
}

// StartTask can be called once to start a task, by a given Runner
func (r *Runner) StartTask(taskID string, titusInfo *titus.ContainerInfo, mem int64, cpu int64, disk uint64) error {
	// This can only be called once!
	t := task{
		taskID:    taskID,
		titusInfo: titusInfo,
		mem:       mem,
		cpu:       cpu,
		disk:      disk,
	}
	select {
	case r.taskChan <- t:
		return nil
	default:
		r.RLock()
		defer r.RUnlock()
		if r.err != nil {
			return r.err
		}
		return errorRunnerAlreadyStarted
	}
}

// Kill is idempotent, and will either kill a task, or prevent a new one from being spawned
func (r *Runner) Kill() {
	r.killOnce.Do(func() {
		close(r.killChan)
	})
}

func (r *Runner) startRunner(parentCtx context.Context, setupCh chan error, rp RuntimeProvider) { // nolint: gocyclo
	defer close(r.UpdatesChan)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer close(r.StoppedChan)

	if err := r.setupRunner(ctx, rp); err != nil {
		setupCh <- err
		return
	}
	close(setupCh)

	// 1. Wait for task to come in for starting
	taskConfig, err := r.waitForTask(parentCtx, ctx)
	r.logger.Info("Received taskConfig to start: ", taskConfig)

	r.logger = r.logger.WithField("taskID", taskConfig.taskID)
	if err != nil {
		r.Lock()
		defer r.Unlock()
		r.err = err
		return
	}

	startTime := time.Now()
	labels := map[string]string{
		models.ExecutorPidLabel: fmt.Sprintf("%d", os.Getpid()),
		models.TaskIDLabel:      taskConfig.taskID,
	}

	// Should we remove this?
	if len(taskConfig.titusInfo.GetIamProfile()) > 0 {
		labels["ec2.iam.role"] = taskConfig.titusInfo.GetIamProfile()
	}

	resources := &runtimeTypes.Resources{
		Mem:  taskConfig.mem,
		CPU:  taskConfig.cpu,
		Disk: taskConfig.disk,
	}
	r.container = runtime.NewContainer(taskConfig.taskID, taskConfig.titusInfo, resources, labels, r.config)

	// TODO: Wire up cleanup callback
	var le launchguardCore.LaunchEvent = &launchguardCore.NoopLaunchEvent{}

	if r.container.TitusInfo.GetIgnoreLaunchGuard() {
		r.logger.Info("Ignoring Launchguard")
	} else {
		// Wait until the launchGuard is released.
		// TODO(Andrew L): We only block concurrent launches to avoid a race condition introduced
		// by the Titus master releasing resources prior to the agent releasing them.
		le = r.launchGuard.NewLaunchEvent(ctx, r.container.TitusInfo.GetNetworkConfigInfo().GetEniLabel())
	}
	if r.config.MetatronEnabled {
		// TODO: Teach metatron about context
		r.container.MetatronConfig, err = r.setupMetatron(ctx)
		defer func() {
			// Remove any Metatron credential stored for the task since they will
			// get copied into the container.
			if err = metatron.RemovePassports(r.container.TaskID); err != nil {
				r.logger.Errorf("Failed to remove Metatron passport dir: %v", err)
			} else {
				r.logger.Infoln("Removed Metadata host passport dir")
			}
		}()
		if err != nil {
			// We are expecting executor container cleanup to remove
			// any files created during the process
			r.logger.Errorf("Failed to acquire Metatron certificates: %s", err)
			r.err = err
			r.updateStatus(ctx, titusdriver.Lost, err.Error())
			return
		}
	}

	// At this point we've begun starting, and we need to explicitly inform the master when the task finishes
	defer r.handleShutdown(ctx)
	select {
	case <-le.Launch():
		r.logger.Info("Launch not blocked on on launchGuard")
		goto no_launchguard
	default:
		r.logger.Info("Launch waiting on launchGuard")
		r.updateStatus(ctx, titusdriver.Starting, WaitingOnLaunchguardMessage)

	}
	select {
	case <-le.Launch():
		r.logger.Info("No longer waiting on launchGuard")
	case <-r.killChan:
		r.logger.Warning("Killed while waiting on launchguard")
		return
	case <-ctx.Done():
		r.logger.Warning("local context done while waiting on launchguard")
		return
	case <-parentCtx.Done():
		r.logger.Warning("Parent context done while waiting on launchguard")
		return
	}

no_launchguard:

	select {
	case <-r.killChan:
		r.logger.Error("Task was killed before task was created")
		return
	case <-ctx.Done():
		r.logger.Error("Task context was terminated before task was created")
		return
	default:
	}
	r.updateStatus(ctx, titusdriver.Starting, "creating")

	// When Create() returns the host may have been modified to create storage and pull the image.
	// These steps may or may not have completed depending on if/where a failure occurred.
	bindMounts := []string{}
	err = r.runtime.Prepare(ctx, r.container, bindMounts)
	if err != nil {
		r.metrics.Counter("titus.executor.launchTaskFailed", 1, nil)
		r.logger.Error("task failed to create container: ", err)
		// Treat registry pull errors as LOST and non-existent images as FAILED.
		switch err.(type) {
		case *runtimeTypes.RegistryImageNotFoundError, *runtimeTypes.InvalidSecurityGroupError, *runtimeTypes.BadEntryPointError:
			r.logger.Error("Returning TASK_FAILED for task: ", err)
			r.updateStatus(ctx, titusdriver.Failed, err.Error())
		default:
			r.logger.Error("Returning TASK_LOST for task: ", err)
			r.updateStatus(ctx, titusdriver.Lost, err.Error())
		}
		return
	}

	r.updateStatus(ctx, titusdriver.Starting, "starting")
	logDir, err := r.runtime.Start(ctx, r.container)
	if err != nil { // nolint: vetshadow
		r.metrics.Counter("titus.executor.launchTaskFailed", 1, nil)
		r.logger.Info("start container: ", err)

		switch err.(type) {
		case *runtimeTypes.BadEntryPointError:
			r.logger.Info("Returning TaskState_TASK_FAILED for task: ", err)
			r.updateStatus(ctx, titusdriver.Failed, err.Error())
		default:
			r.logger.Info("Returning TASK_LOST for task: ", err)
			r.updateStatus(ctx, titusdriver.Lost, err.Error())
		}
		return
	}

	if logDir != "" {
		r.logger.Info("Starting external logger")
		err = r.maybeSetupExternalLogger(ctx, logDir)
		if err != nil {
			r.logger.Error("Unable to setup logging for container: ", err)
			r.updateStatus(ctx, titusdriver.Lost, err.Error())
			return
		}
	} else {
		r.logger.Info("Not starting external logger")
	}

	// TODO(fabio): Start should return Details
	details, err := r.runtime.Details(r.container)
	if err != nil {
		r.logger.Error("Error fetching details for task: ", err)
		r.updateStatus(ctx, titusdriver.Lost, err.Error())
		return
	} else if details == nil {
		r.logger.Error("Unable to fetch task details")
	}
	r.metrics.Counter("titus.executor.taskLaunched", 1, nil)
	r.updateStatusWithDetails(ctx, titusdriver.Running, "running", details)

	// report metrics for startup time, docker image size
	r.metrics.Timer("titus.executor.containerStartTime", time.Since(startTime), r.container.ImageTagForMetrics())

	ticks := time.NewTicker(r.config.StatusCheckFrequency)
	defer ticks.Stop()

	for {
		select {
		case <-ticks.C:
			status, err := r.runtime.Status(r.container)
			if err != nil {
				r.logger.Error("Status result error: ", err)
			}
			shouldQuit, titusTaskStatus, msg := parseStatus(status, err)
			if shouldQuit {
				r.logger.Info("Status: ", titusTaskStatus.String())
				// TODO: Generate Update
				r.updateStatus(ctx, titusTaskStatus, msg)
				return
			}
		case <-r.killChan:
			r.logger.Info("Received kill signal")
			return
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runner) handleShutdown(ctx context.Context) { // nolint: gocyclo
	r.logger.Debug("Handling shutdown")
	launchGuardCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cleanupErrs []error
	var ce launchguardCore.CleanUpEvent = &launchguardCore.NoopCleanUpEvent{}

	if r.wasKilled() {
		r.logger.Info("Setting launchGuard while stopping task")
		ce = r.launchGuard.NewRealCleanUpEvent(launchGuardCtx, r.container.TitusInfo.GetNetworkConfigInfo().GetEniLabel())
	}

	killStartTime := time.Now()
	// Are we in a situation where the container exited gracefully, or less than gracefully?
	// We need to stop the container
	if err := r.runtime.Kill(r.container); err != nil {
		// TODO(Andrew L): There may be leaked resources that are not being
		// accounted for. Consider forceful cleanup or tracking leaked resources.
		r.logger.Error("Failed to fully complete primary kill actions: ", err)
		switch r.lastStatus {
		case titusdriver.Finished:
		case titusdriver.Failed:
		default:
			cleanupErrs = append(cleanupErrs, err)
		}
	}
	/* If this flag is not set to true, we've been launched by the v2 engine
	 * therefore we can have a task started on this ENI instanteoously after a launch
	 *
	 * Otherwise, we hold the launchguard until all cleanup is completed
	 */
	if !r.container.TitusInfo.GetIgnoreLaunchGuard() {
		r.logger.Info("Unsetting launchguard")
		ce.Done()
	} else {
		defer ce.Done()
	}

	if r.watcher != nil {
		if err := r.watcher.Stop(); err != nil {
			r.logger.Error("Error while shutting down watcher for: ", err)
			cleanupErrs = append(cleanupErrs, err)
		}
	}
	if err := r.runtime.Cleanup(r.container); err != nil {
		r.logger.Error("Cleanup failed: ", err)
		cleanupErrs = append(cleanupErrs, err)
	}
	r.metrics.Counter("titus.executor.taskCleanupDone", 1, nil)
	msg := ""
	if len(cleanupErrs) > 0 {
		msg = fmt.Sprintf("%+v", cleanupErrs)
	}

	if r.lastStatus == titusdriver.Finished {
		// TODO(Andrew L): There may be leaked resources that are not being
		// accounted for. Consider forceful cleanup or tracking leaked resources.
		// If the task finished successfully, include any info about cleanup errors
		msg = fmt.Sprintf("%+v", cleanupErrs)
		r.updateStatus(ctx, r.lastStatus, msg)
	} else if r.wasKilled() {
		r.updateStatus(ctx, titusdriver.Killed, msg)
	}
	if r.lastStatus == titusdriver.Running || r.lastStatus == titusdriver.Starting {
		r.updateStatus(ctx, titusdriver.Lost, "Container lost -- Unknown")
		r.logger.Error("Container killed while non-terminal!")
	}

	r.metrics.Timer("titus.executor.containerCleanupTime", time.Since(killStartTime), r.container.ImageTagForMetrics())
}

func (r *Runner) wasKilled() bool {
	select {
	case <-r.killChan:
		return true
	default:
		return false
	}
}

func parseStatus(status runtimeTypes.Status, err error) (bool, titusdriver.TitusTaskState, string) {

	switch status {
	case runtimeTypes.StatusRunning:
		// no need to Update the status if task is running
		return false, titusdriver.Running, ""
	case runtimeTypes.StatusFinished:
		return true, titusdriver.Finished, "finished"
	case runtimeTypes.StatusFailed:
		return true, titusdriver.Failed, err.Error()
	default:
		return true, titusdriver.Lost, err.Error()
	}
}

func (r *Runner) maybeSetupExternalLogger(ctx context.Context, logDir string) error {
	var err error

	uploadDir := r.container.UploadDir("logs")
	uploadRegex := r.container.TitusInfo.GetLogUploadRegexp()
	r.watcher, err = filesystems.NewWatcher(r.metrics, logDir, uploadDir, uploadRegex, r.logUploaders, r.config)
	if err != nil {
		return err
	}

	return r.watcher.Watch(ctx)
}

// setupMetatron returns a Docker formatted string bind mount for a container for a directory that will contain
func (r *Runner) setupMetatron(ctx context.Context) (*metatron.CredentialsConfig, error) {
	if r.container.TitusInfo.GetMetatronCreds() == nil {
		return nil, nil
	}

	r.updateStatus(ctx, titusdriver.Starting, "creating_metatron")

	mts, err := metatron.InitMetatronTruststore()
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize Metatron trust store: %s", err)
	}

	envMap := r.container.TitusInfo.GetUserProvidedEnv()
	if envMap == nil {
		envMap = make(map[string]string)
	}

	titusMetadata := metatron.TitusMetadata{
		App:          r.container.TitusInfo.GetAppName(),
		Stack:        r.container.TitusInfo.GetJobGroupStack(),
		ImageName:    r.container.TitusInfo.GetImageName(),
		ImageVersion: r.container.TitusInfo.GetVersion(),
		Entrypoint:   r.container.TitusInfo.GetEntrypointStr(),
		Env:          envMap,
		TaskID:       r.container.TaskID,
		LaunchTime:   (time.Now().UnixNano() / int64(time.Millisecond)),
	}

	metatronConfig, err := mts.GetPassports(
		r.container.TitusInfo.MetatronCreds.AppMetadata,
		r.container.TitusInfo.MetatronCreds.MetadataSig,
		r.container.TaskID,
		titusMetadata)
	if err != nil {
		r.logger.Error("Get Metatron Passport credentials failed: ", err)
		return nil, err
	}
	r.logger.Info("Retrieved Metatron Passport credentials")
	return metatronConfig, nil
}

func (r *Runner) waitForTask(parentCtx, ctx context.Context) (*task, error) {
	timer := time.NewTimer(waitForTaskTimeout)
	defer timer.Stop()
	defer close(r.taskChan)
	select {
	case <-parentCtx.Done():
		return nil, ctx.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	case tsk := <-r.taskChan:
		return &tsk, nil
	case <-timer.C:
		return nil, errorTaskWaitTimeout
	}
}

func (r *Runner) setupRunner(ctx context.Context, rp RuntimeProvider) error {
	var err error

	r.runtime, err = rp(ctx, r.config)
	return err
}

func (r *Runner) updateStatus(ctx context.Context, status titusdriver.TitusTaskState, msg string) {
	r.updateStatusWithDetails(ctx, status, msg, nil)
}

func (r *Runner) updateStatusWithDetails(ctx context.Context, status titusdriver.TitusTaskState, msg string, details *runtimeTypes.Details) {
	r.lastStatus = status
	l := r.logger.WithField("msg", msg).WithField("taskStatus", status)
	if details != nil {
		l = l.WithField("details", details)
	}
	select {
	case r.UpdatesChan <- Update{
		TaskID:  r.container.TaskID,
		State:   status,
		Mesg:    msg,
		Details: details,
	}:
		l.Info("Updating task status")
	case <-ctx.Done():
		l.Info("Not sending update")
	}
}

// Update encapsulates information on the updatechan about task status updates
type Update struct {
	TaskID  string
	State   titusdriver.TitusTaskState
	Mesg    string
	Details *runtimeTypes.Details
}

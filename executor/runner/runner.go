package runner

import (
	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/metatron"
	"github.com/Netflix/titus-executor/executor/runtime"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/filesystems"
	"github.com/Netflix/titus-executor/models"
	"github.com/Netflix/titus-executor/uploader"
	"github.com/hashicorp/go-multierror"
	"github.com/sirupsen/logrus"

	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

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
	metrics metrics.Reporter
	runtime runtimeTypes.Runtime
	config  config.Config
	logger  *logrus.Entry

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
	runner := &Runner{
		logger:       logrus.NewEntry(logrus.StandardLogger()),
		metrics:      m,
		logUploaders: logUploaders,
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

	if err := <-setupCh; err != nil {
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

	// We must ensure that setupCh is closed, or returns an error.
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

	if r.config.MetatronEnabled {
		err = r.setupMetatron()
		if err != nil {
			r.err = err
			r.logger.Error("Failed to acquire Metatron certificates: ", err)
			r.updateStatus(ctx, titusdriver.Lost, err.Error())
			return
		}
	}

	// At this point we've begun starting, and we need to explicitly inform the master when the task finishes
	defer r.handleShutdown(ctx)

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

	prepareCtx, prepareCancel := context.WithCancel(ctx)
	defer prepareCancel()
	go func() {
		select {
		case <-r.killChan:
			prepareCancel()
		case <-prepareCtx.Done():
		}
	}()
	// When Create() returns the host may have been modified to create storage and pull the image.
	// These steps may or may not have completed depending on if/where a failure occurred.
	bindMounts := []string{}
	err = r.runtime.Prepare(prepareCtx, r.container, bindMounts)
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

	// By this point, we should have no more dependence on the prepare context
	prepareCancel()
	r.updateStatus(ctx, titusdriver.Starting, "starting")
	logDir, details, statusChan, err := r.runtime.Start(ctx, r.container)
	if err != nil { // nolint: vetshadow
		r.metrics.Counter("titus.executor.launchTaskFailed", 1, nil)
		r.logger.Info("start container: ", err)

		switch err.(type) {
		case *runtimeTypes.BadEntryPointError:
			r.logger.Info("Returning TaskState_TASK_FAILED for task: ", err)
			r.updateStatusWithDetails(ctx, titusdriver.Failed, err.Error(), details)
		default:
			r.logger.Info("Returning TASK_LOST for task: ", err)
			r.updateStatusWithDetails(ctx, titusdriver.Lost, err.Error(), details)
		}
		return
	}

	if logDir != "" {
		r.logger.Info("Starting external logger")
		err = r.maybeSetupExternalLogger(ctx, logDir)
		if err != nil {
			r.logger.Error("Unable to setup logging for container: ", err)
			r.updateStatusWithDetails(ctx, titusdriver.Lost, err.Error(), details)
			return
		}
	} else {
		r.logger.Info("Not starting external logger")
	}

	if details == nil {
		r.logger.Fatal("Unable to fetch task details")
	}
	r.metrics.Counter("titus.executor.taskLaunched", 1, nil)

	r.monitorContainer(ctx, startTime, statusChan, details)
}

func (r *Runner) monitorContainer(ctx context.Context, startTime time.Time, statusChan <-chan runtimeTypes.StatusMessage, details *runtimeTypes.Details) { // nolint: gocyclo
	lastMessage := ""
	runningSent := false

	for {
		select {
		case statusMessage, ok := <-statusChan:
			msg := statusMessage.Msg
			if !ok {
				r.updateStatusWithDetails(ctx, titusdriver.Lost, "Lost connection to runtime driver", details)
				return
			}
			r.logger.WithField("statusMessage", statusMessage).Info("Processing msg")

			switch statusMessage.Status {
			case runtimeTypes.StatusRunning:
				r.handleTaskRunningMessage(ctx, msg, &lastMessage, &runningSent, startTime, details)
				// Error code 0
			case runtimeTypes.StatusFinished:
				if msg == "" {
					msg = "finished"
				}
				r.updateStatusWithDetails(ctx, titusdriver.Finished, msg, details)
				return
			case runtimeTypes.StatusFailed:
				r.updateStatusWithDetails(ctx, titusdriver.Failed, msg, details)
				return
			default:
				r.updateStatusWithDetails(ctx, titusdriver.Lost, msg, details)
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

func (r *Runner) handleTaskRunningMessage(ctx context.Context, msg string, lastMessage *string, runningSent *bool, startTime time.Time, details *runtimeTypes.Details) {
	// no need to Update the status if task is running and the message is the same as the last one
	// The first time this is called *runningSent should be false, so it'll always trigger
	if msg == *lastMessage && *runningSent {
		return
	}

	// The msg for the first runningSent will always be "running"
	if !(*runningSent) {
		if msg == "" {
			msg = "running"
		}
		r.metrics.Timer("titus.executor.containerStartTime", time.Since(startTime), r.container.ImageTagForMetrics())
	}

	r.updateStatusWithDetails(ctx, titusdriver.Running, msg, details)
	*runningSent = true
	*lastMessage = msg

}

func (r *Runner) handleShutdown(ctx context.Context) { // nolint: gocyclo
	r.logger.Debug("Handling shutdown")
	var errs *multierror.Error

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
			errs = multierror.Append(errs, err)
		}
	}

	if r.watcher != nil {
		if err := r.watcher.Stop(); err != nil {
			r.logger.Error("Error while shutting down watcher for: ", err)
			errs = multierror.Append(errs, err)
		}
	}
	if err := r.runtime.Cleanup(r.container); err != nil {
		r.logger.Error("Cleanup failed: ", err)
		errs = multierror.Append(errs, err)
	}
	r.metrics.Counter("titus.executor.taskCleanupDone", 1, nil)
	msg := ""
	if err := errs.ErrorOrNil(); err != nil {
		msg = fmt.Sprintf("%+v", err)
	}

	if r.lastStatus == titusdriver.Finished {
		// TODO(Andrew L): There may be leaked resources that are not being
		// accounted for. Consider forceful cleanup or tracking leaked resources.
		// If the task finished successfully, include any info about cleanup errors
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

// mkGetMetatronConfigFunc is broken out into its own function to prevent accidentally capturing environment we shouldn't.
func mkGetMetatronConfigFunc(mts *metatron.TrustStore) func(ctx context.Context, c *runtimeTypes.Container) (*metatron.CredentialsConfig, error) {
	return func(ctx context.Context, c *runtimeTypes.Container) (*metatron.CredentialsConfig, error) {
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
			IPAddress:    c.Allocation.IPV4Address,
			Env:          envMap,
			TaskID:       c.TaskID,
			LaunchTime:   (time.Now().UnixNano() / int64(time.Millisecond)),
		}

		metatronConfig, err := mts.GetPassports(
			ctx,
			c.TitusInfo.MetatronCreds.AppMetadata,
			c.TitusInfo.MetatronCreds.MetadataSig,
			c.TaskID,
			titusMetadata)
		if err != nil {
			return nil, fmt.Errorf("Get Metatron Passport credentials failed: %s", err.Error())
		}
		return metatronConfig, nil
	}
}

// setupMetatron returns a Docker formatted string bind mount for a container for a directory that will contain
func (r *Runner) setupMetatron() error {
	if r.container.TitusInfo.GetMetatronCreds() == nil {
		return nil
	}
	mts, err := metatron.InitMetatronTruststore()
	if err != nil {
		return fmt.Errorf("Failed to initialize Metatron trust store: %s", err)
	}

	r.container.GetMetatronConfig = mkGetMetatronConfigFunc(mts)
	return nil
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
	select {
	case r.UpdatesChan <- Update{
		TaskID:  r.container.TaskID,
		State:   status,
		Mesg:    msg,
		Details: details,
	}:
		l.Info("Updating task status")
	case <-ctx.Done():
		l.Warn("Not sending update, because UpdatesChan Blocked, (or closed), and context completed")
	}
}

// Update encapsulates information on the updatechan about task status updates
type Update struct {
	TaskID  string
	State   titusdriver.TitusTaskState
	Mesg    string
	Details *runtimeTypes.Details
}

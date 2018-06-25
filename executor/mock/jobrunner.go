package mock

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	"github.com/Netflix/titus-executor/uploader"
	protobuf "github.com/golang/protobuf/proto"
	"github.com/pborman/uuid"
	log "github.com/sirupsen/logrus"
)

var errStatusChannelClosed = errors.New("Status channel closed")

// JobInput contains basic config info for a test job to run
type JobInput struct {
	// JobID is the name of the Titus job
	JobID string
	// ImageName is the name of the docker image
	ImageName string
	// Version is the name of the Docker image tag
	Version string
	// ImageDigest is a unique identifier of the image
	ImageDigest string
	// Entrypoint is the name of the Docker entrypoint
	Entrypoint string
	// Capabilities to add
	Capabilities *titus.ContainerInfo_Capabilities
	// Environment  is any extra environment variables to add
	Environment map[string]string
	// IgnoreLaunchGuard sets the V3 engine flag on the job
	IgnoreLaunchGuard bool
	// Batch sets batch mode on the task
	Batch string
	// CPUBursting sets the CPU bursting protobuf attribute
	CPUBursting bool
	// CPU sets the CPU count resource attribute
	CPU *int64
	// StopTimeoutSeconds is the duration we wait after SIGTERM for the container to exit
	KillWaitSeconds uint32
}

// JobRunResponse returned from RunJob
type JobRunResponse struct {
	runner     *runner.Runner
	TaskID     string
	UpdateChan chan runner.Update
}

// WaitForSuccess blocks on the jobs completion and returns true
// if it completed successfully.
func (jobRunResponse *JobRunResponse) WaitForSuccess() bool {
	status, err := jobRunResponse.WaitForCompletion()
	if err != nil {
		return false
	}
	return status == "TASK_FINISHED"
}

// WaitForFailure blocks on the jobs completion and returns true
// if it exits with a non-zero (user) error
func (jobRunResponse *JobRunResponse) WaitForFailure() bool {
	status, err := jobRunResponse.WaitForCompletion()
	if err != nil {
		return false
	}
	return status == "TASK_FAILED"
}

// WaitForCompletion blocks on the jobs completion and returns its status
// if it completed successfully.
func (jobRunResponse *JobRunResponse) WaitForCompletion() (string, error) {
	for status := range jobRunResponse.runner.UpdatesChan {
		if status.State.String() == "TASK_RUNNING" || status.State.String() == "TASK_STARTING" {
			continue // Ignore non-terminal states
		}
		return status.State.String(), nil
	}
	return "TASK_LOST", errStatusChannelClosed
}

// ListenForRunning sends true on the returned channel when the task is running, or false if it terminates
func (jobRunResponse *JobRunResponse) ListenForRunning() <-chan bool {
	notify := make(chan bool, 1) // max one message to be sent
	go func() {
		for status := range jobRunResponse.runner.UpdatesChan {
			if status.State == titusdriver.Running {
				notify <- true
				close(notify)
				return
			} else if status.State.IsTerminalStatus() {
				notify <- false
				close(notify)
				return
			}
		}
	}()
	return notify
}

// JobRunner is the entrypoint struct to create an executor and run test jobs on it
type JobRunner struct {
	runner          *runner.Runner
	ctx             context.Context
	cancel          context.CancelFunc
	shutdownChannel chan struct{}
}

// NewJobRunner creates a new JobRunner with its executor started
// in the background and the test driver configured to use it.
func NewJobRunner() *JobRunner {
	// Load a specific config for testing and disable metrics
	cfg, err := config.GenerateConfiguration([]string{"--copy-uploader", "/var/tmp/titus-executor/tests"})
	if err != nil {
		panic(err)
	}
	cfg.KeepLocalFileAfterUpload = true
	cfg.MetatronEnabled = false

	dockerCfg, err := docker.GenerateConfiguration(nil)
	if err != nil {
		panic(err)
	}

	// Create an executor
	logUploaders, err := uploader.NewUploaders(cfg)
	if err != nil {
		log.Fatalf("cannot create log uploaders: %s", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	// TODO: Replace this config mechanism
	r, err := runner.New(ctx, metrics.Discard, logUploaders, *cfg, *dockerCfg)
	if err != nil {
		log.Fatalf("cannot create executor : %s", err)
	}

	jobRunner := &JobRunner{
		ctx: ctx, cancel: cancel,
		runner:          r,
		shutdownChannel: make(chan struct{}),
	}

	return jobRunner
}

var r = rand.New(rand.NewSource(999))

// StopExecutor stops a currently running executor
func (jobRunner *JobRunner) StopExecutor() {
	jobRunner.cancel()
	<-jobRunner.runner.StoppedChan
}

// StopExecutorAsync stops a currently running executor
func (jobRunner *JobRunner) StopExecutorAsync() {
	jobRunner.cancel()
}

// StartJob starts a job on an existing JobRunner and returns once the job is started
func (jobRunner *JobRunner) StartJob(jobInput *JobInput) *JobRunResponse {
	// Define some stock job to run
	var jobID string
	if jobInput.JobID == "" {
		jobID = fmt.Sprintf("Titus-%v%v", r.Intn(1000), time.Now().Second())
	} else {
		jobID = jobInput.JobID
	}
	taskID := fmt.Sprintf("Titus-%v%v-Worker-0-2", r.Intn(1000), time.Now().Second())
	env := map[string]string{
		"TITUS_TASK_ID":          taskID,
		"TITUS_TASK_INSTANCE_ID": uuid.New(),
		"EC2_LOCAL_IPV4":         "1.2.3.4",
	}

	// range over nil is safe
	for k, v := range jobInput.Environment {
		env[k] = v
	}

	ci := &titus.ContainerInfo{
		ImageName:     protobuf.String(jobInput.ImageName),
		Version:       protobuf.String(jobInput.Version),
		EntrypointStr: protobuf.String(jobInput.Entrypoint),
		JobId:         protobuf.String(jobID),
		AppName:       protobuf.String("myapp"),
		NetworkConfigInfo: &titus.ContainerInfo_NetworkConfigInfo{
			EniLabel: protobuf.String("1"),
		},
		IamProfile:            protobuf.String("arn:aws:iam::0:role/DefaultContainerRole"),
		Capabilities:          jobInput.Capabilities,
		TitusProvidedEnv:      env,
		IgnoreLaunchGuard:     protobuf.Bool(jobInput.IgnoreLaunchGuard),
		PassthroughAttributes: make(map[string]string),
	}

	if jobInput.Batch != "" {
		ci.Batch = protobuf.Bool(true)
	}
	if jobInput.Batch == "idle" {
		ci.PassthroughAttributes["titusParameter.agent.batchPriority"] = "idle"
	}

	if jobInput.KillWaitSeconds > 0 {
		ci.KillWaitSeconds = protobuf.Uint32(jobInput.KillWaitSeconds)
	}
	if id := jobInput.ImageDigest; id != "" {
		ci.ImageDigest = protobuf.String(id)
	}

	ci.AllowCpuBursting = protobuf.Bool(jobInput.CPUBursting)
	cpu := int64(1)
	if jobInput.CPU != nil {
		cpu = *jobInput.CPU
	}
	memMiB := int64(400)
	diskMiB := uint64(100)

	// Get a reference to the executor and somewhere to stash results

	// Start the task and wait for it to complete
	err := jobRunner.runner.StartTask(taskID, ci, memMiB, cpu, diskMiB)
	if err != nil {
		log.Printf("Failed to start task %s: %s", taskID, err)
	}
	jrr := &JobRunResponse{
		runner:     jobRunner.runner,
		TaskID:     taskID,
		UpdateChan: jobRunner.runner.UpdatesChan,
	}

	return jrr
}

// KillTask issues a kill task request to the executor. The kill
// may be done in the background and the state change should occur
// on the existing JobRunResponse channel.
func (jobRunner *JobRunner) KillTask() error {
	jobRunner.runner.Kill()
	<-jobRunner.runner.StoppedChan
	return nil
}

// RunJobExpectingSuccess is similar to RunJob but returns true when the task completes successfully.
func RunJobExpectingSuccess(jobInput *JobInput) bool {
	jobRunner := NewJobRunner()
	defer jobRunner.StopExecutor()

	jobResult := jobRunner.StartJob(jobInput)
	return jobResult.WaitForSuccess()
}

// RunJobExpectingFailure is similar to RunJob but returns true when the task completes successfully.
func RunJobExpectingFailure(jobInput *JobInput) bool {
	jobRunner := NewJobRunner()
	defer jobRunner.StopExecutor()

	jobResult := jobRunner.StartJob(jobInput)
	return jobResult.WaitForFailure()
}

// RunJob runs a single Titus task based on provided JobInput
func RunJob(jobInput *JobInput) (string, error) {
	jobRunner := NewJobRunner()
	defer jobRunner.StopExecutor()

	jobResult := jobRunner.StartJob(jobInput)
	return jobResult.WaitForCompletion()
}

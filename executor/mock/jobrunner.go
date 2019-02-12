package mock

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	metadataserverTypes "github.com/Netflix/titus-executor/metadataserver/types"
	"github.com/Netflix/titus-executor/uploader"
	protobuf "github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
)

var errStatusChannelClosed = errors.New("Status channel closed")

const metatronTestImage = "titusoss/metatron:20190115-1547588673"

// Process describes what runs inside the container
type Process struct {
	Entrypoint []string
	// Cmd overrides what is in the image
	Cmd []string
}

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
	// EntrypointOld is the deprecated way of passing an entrypoint as a flat string
	EntrypointOld string
	// Process is the new way of passing entrypoint and cmd
	Process *Process
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
	// Tty attaches a tty to the container via a passthrough attribute
	Tty bool
	// MetatronEnabled enables running with the metatron sidecar container
	MetatronEnabled bool
	// Mem sets the memory resource attribute in MiB
	Mem *int64
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

// WaitForFailureWithStatus blocks until the job is finished, or ctx expires, and returns no error if the exit status
// code matches the the desired value
func (jobRunResponse *JobRunResponse) WaitForFailureWithStatus(ctx context.Context, exitStatus int) error {
	for {
		select {
		case status, ok := <-jobRunResponse.UpdateChan:
			if !ok {
				return errors.New("UpdateChan closed before TASK_FAIL")
			}
			if !status.State.IsTerminalStatus() {
				continue
			}
			if status.State == titusdriver.Failed {
				if !strings.Contains(status.Mesg, fmt.Sprintf("exited with code %d", exitStatus)) {
					return fmt.Errorf("Did not exit with status %d: %s", exitStatus, status.Mesg)
				}
				return nil // success
			}
			return fmt.Errorf("Terminal state is not TASK_FAILED: %s", status.State.String())
		case <-ctx.Done():
			return ctx.Err()
		}
	}
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

// GenerateConfigs generates test configs
func GenerateConfigs(jobInput *JobInput) (*config.Config, *docker.Config) {
	cfg, err := config.GenerateConfiguration([]string{"--copy-uploader", "/var/tmp/titus-executor/tests"})
	if err != nil {
		panic(err)
	}

	if jobInput != nil && jobInput.MetatronEnabled {
		cfg.MetatronEnabled = true
		cfg.ContainerMetatronImage = metatronTestImage
	}

	dockerCfg, err := docker.GenerateConfiguration(nil)
	if err != nil {
		panic(err)
	}

	return cfg, dockerCfg
}

// NewJobRunner creates a new JobRunner with its executor started
// in the background and the test driver configured to use it.
func NewJobRunner(jobInput *JobInput) *JobRunner {
	cfg, dockerCfg := GenerateConfigs(jobInput)

	// Create an executor
	logUploaders, err := uploader.NewUploaders(cfg, metrics.Discard)
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
		ctx:             ctx,
		cancel:          cancel,
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
func (jobRunner *JobRunner) StartJob(jobInput *JobInput) *JobRunResponse { // nolint: gocyclo
	// Define some stock job to run
	var jobID string

	if jobInput.JobID == "" {
		jobID = fmt.Sprintf("Titus-%v%v", r.Intn(1000), time.Now().Second())
	} else {
		jobID = jobInput.JobID
	}

	// TODO: refactor this all to use NewContainer()
	taskID := fmt.Sprintf("Titus-%v%v-Worker-0-2", r.Intn(1000), time.Now().Second())

	env := map[string]string{
		"TITUS_TASK_ID":          taskID,
		"TITUS_TASK_INSTANCE_ID": taskID,
		"EC2_LOCAL_IPV4":         "1.2.3.4",
	}

	if jobInput.MetatronEnabled {
		env[metadataserverTypes.TitusMetatronVariableName] = "true"
	} else {
		env[metadataserverTypes.TitusMetatronVariableName] = "false"
	}

	// range over nil is safe
	for k, v := range jobInput.Environment {
		env[k] = v
	}

	ci := &titus.ContainerInfo{
		ImageName: protobuf.String(jobInput.ImageName),
		Version:   protobuf.String(jobInput.Version),
		JobId:     protobuf.String(jobID),
		AppName:   protobuf.String("myapp"),
		NetworkConfigInfo: &titus.ContainerInfo_NetworkConfigInfo{
			EniLabel:  protobuf.String("1"),
			EniLablel: protobuf.String("1"), // deprecated, but protobuf marshaling raises an error if it's not present
		},
		IamProfile:        protobuf.String("arn:aws:iam::0:role/DefaultContainerRole"),
		Capabilities:      jobInput.Capabilities,
		TitusProvidedEnv:  env,
		IgnoreLaunchGuard: protobuf.Bool(jobInput.IgnoreLaunchGuard),
		PassthroughAttributes: map[string]string{
			runtimeTypes.LogKeepLocalFileAfterUploadParam: "true",
		},
	}

	if p := jobInput.Process; p != nil {
		ci.Process = &titus.ContainerInfo_Process{
			Entrypoint: p.Entrypoint,
			Command:    p.Cmd,
		}
	} else {
		ci.EntrypointStr = protobuf.String(jobInput.EntrypointOld)
	}
	if jobInput.Batch != "" {
		ci.Batch = protobuf.Bool(true)
	}
	if jobInput.Batch == "idle" {
		ci.PassthroughAttributes["titusParameter.agent.batchPriority"] = "idle"
	}
	if jobInput.Tty {
		ci.PassthroughAttributes["titusParameter.agent.ttyEnabled"] = "true"
	}

	if jobInput.MetatronEnabled {
		ci.MetatronCreds = &titus.ContainerInfo_MetatronCreds{
			AppMetadata: protobuf.String("fake-metatron-app"),
			MetadataSig: protobuf.String("fake-metatron-sig"),
		}
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
	if jobInput.Mem != nil {
		memMiB = *jobInput.Mem
	}
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
	jobRunner := NewJobRunner(jobInput)
	defer jobRunner.StopExecutor()

	jobResult := jobRunner.StartJob(jobInput)
	return jobResult.WaitForSuccess()
}

// RunJobExpectingFailure is similar to RunJob but returns true when the task completes successfully.
func RunJobExpectingFailure(jobInput *JobInput) bool {
	jobRunner := NewJobRunner(jobInput)
	defer jobRunner.StopExecutor()

	jobResult := jobRunner.StartJob(jobInput)
	return jobResult.WaitForFailure()
}

// RunJob runs a single Titus task based on provided JobInput
func RunJob(jobInput *JobInput) (string, error) {
	jobRunner := NewJobRunner(jobInput)
	defer jobRunner.StopExecutor()

	jobResult := jobRunner.StartJob(jobInput)
	return jobResult.WaitForCompletion()
}

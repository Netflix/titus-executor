package mock

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor"
	"github.com/Netflix/titus-executor/executor/drivers/test"
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
	// StopTimeoutSeconds is the duration we wait after SIGTERM for the container to exit
	KillWaitSeconds uint32
}

// JobRunResponse returned from RunJob
type JobRunResponse struct {
	StatusChannel chan string
	TaskID        string
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

// WaitForCompletion blocks on the jobs completion and returns its status
// if it completed successfully.
func (jobRunResponse *JobRunResponse) WaitForCompletion() (string, error) {
	for status := range jobRunResponse.StatusChannel {
		if status == "TASK_RUNNING" || status == "TASK_STARTING" {
			continue // Ignore non-terminal states
		}
		return status, nil
	}
	return "TASK_LOST", errStatusChannelClosed
}

// ListenForRunning sends true on the returned channel when the task is running, or false if it terminates
func (jobRunResponse *JobRunResponse) ListenForRunning() <-chan bool {
	notify := make(chan bool, 1) // max one message to be sent
	go func() {
		for status := range jobRunResponse.StatusChannel {
			if status == "TASK_RUNNING" {
				notify <- true
				close(notify)
				return
			} else if IsTerminalState(status) {
				notify <- false
				close(notify)
				return
			}
		}
	}()
	return notify
}

// IsTerminalState returns true if the task status is a terminal state
func IsTerminalState(taskStatus string) bool {
	return taskStatus == "TASK_FINISHED" || taskStatus == "TASK_FAILED" ||
		taskStatus == "TASK_KILLED" || taskStatus == "TASK_LOST"
}

// NewJobRunResponse returns a new struct to handle responses from a running job
func NewJobRunResponse(taskID string) *JobRunResponse {
	return &JobRunResponse{
		StatusChannel: make(chan string, 10),
		TaskID:        taskID,
	}
}

// JobRunner is the entrypoint struct to create an executor and run test jobs on it
type JobRunner struct {
	executor        *executor.Executor
	testDriver      *testdriver.TitusTestDriver
	taskResponseMap map[string]*JobRunResponse
	shutdownChannel chan struct{}
	HTTPServer      *httptest.Server
}

// NewJobRunner creates a new JobRunner with its executor started
// in the background and the test driver configured to use it.
func NewJobRunner(startHTTPServer bool) *JobRunner {
	// Load a specific config for testing and disable metrics
	config.Load(context.TODO(), "../config.json")

	// Create an executor
	logUploaders, err := uploader.NewUploaders(config.Uploaders().Log)
	if err != nil {
		log.Fatalf("cannot create log uploaders: %s", err)
	}
	e, err := executor.New(metrics.Discard, logUploaders)
	if err != nil {
		log.Fatalf("cannot create executor : %s", err)
	}

	// Create a test driver
	var testDriver *testdriver.TitusTestDriver
	testDriver, err = testdriver.New(e) // nolint: ineffassign
	if err != nil {
		log.Fatalf("cannot create test driver: %+v", err)
	}

	// Start the executor in the background
	go e.Start()

	jobRunner := &JobRunner{
		executor:        e,
		testDriver:      testDriver,
		taskResponseMap: make(map[string]*JobRunResponse),
		shutdownChannel: make(chan struct{}),
	}

	// If requested, start an HTTP server for the executor
	var httpServer *httptest.Server
	if startHTTPServer {
		go func() {
			httpServer = httptest.NewServer(e.GetServeMux())
			jobRunner.HTTPServer = httpServer
		}()
	}

	// Start a go routine to monitor status in the background
	go jobRunner.MonitorTask()

	return jobRunner
}

var r = rand.New(rand.NewSource(999))

// StopExecutor stops a currently running executor
func (jobRunner *JobRunner) StopExecutor() {
	if jobRunner.HTTPServer != nil {
		defer jobRunner.HTTPServer.Close()
	}
	jobRunner.executor.Stop()
	close(jobRunner.shutdownChannel)
}

// StopExecutorAsync stops a currently running executor
func (jobRunner *JobRunner) StopExecutorAsync() {
	go jobRunner.StopExecutor()
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
		IamProfile:        protobuf.String("arn:aws:iam::0:role/DefaultContainerRole"),
		Capabilities:      jobInput.Capabilities,
		TitusProvidedEnv:  env,
		IgnoreLaunchGuard: protobuf.Bool(jobInput.IgnoreLaunchGuard),
	}

	if jobInput.KillWaitSeconds > 0 {
		ci.KillWaitSeconds = protobuf.Uint32(jobInput.KillWaitSeconds)
	}
	if id := jobInput.ImageDigest; id != "" {
		ci.ImageDigest = protobuf.String(id)
	}
	cpu := int64(1)
	memMiB := int64(400)
	diskMiB := uint64(100)
	var ports []uint16

	// Get a reference to the executor and somewhere to stash results
	e := jobRunner.executor
	jobResult := NewJobRunResponse(taskID)
	jobRunner.taskResponseMap[taskID] = jobResult

	// Start the task and wait for it to complete
	err := e.StartTask(taskID, ci, memMiB, cpu, diskMiB, ports)
	if err != nil {
		log.Printf("Failed to start task %s: %s", taskID, err)
		go func() { jobResult.StatusChannel <- "TASK_LOST" }()
	}
	return jobResult
}

// KillTask issues a kill task request to the executor. The kill
// may be done in the background and the state change should occur
// on the existing JobRunResponse channel.
func (jobRunner *JobRunner) KillTask(taskID string) error {
	return jobRunner.executor.StopTask(taskID)
}

// GetNumTasks returns the number of current tasks
func (jobRunner *JobRunner) GetNumTasks() int {
	return jobRunner.executor.GetNumTasks()
}

// MonitorTask is a blocking call that monitors all status from a
// driver and forwards them to per-task status channels.
func (jobRunner *JobRunner) MonitorTask() {
	for {
		select {
		case taskStatus := <-jobRunner.testDriver.StatusChannel:
			if jobResult, exists := jobRunner.taskResponseMap[taskStatus.TaskID]; exists {
				log.WithField("taskID", taskStatus.TaskID).Info("Forwarding status update: ", taskStatus.Status)
				jobResult.StatusChannel <- taskStatus.Status
			} else {
				log.Infof("Received a status for unknown task %s", taskStatus.TaskID)
			}
			// Remove tasks with terminal states from the map
			if IsTerminalState(taskStatus.Status) {
				log.Infof("Deleting task %s from map because state is %s", taskStatus.TaskID, taskStatus.Status)
				delete(jobRunner.taskResponseMap, taskStatus.TaskID)
			}
		case <-jobRunner.shutdownChannel:
			return
		}
	}
}

// ContainerID returns the runtime specific container ID for a task. It is set after the container is created.
func (jobRunner *JobRunner) ContainerID(taskID string) string {
	return jobRunner.executor.ContainerID(taskID)
}

// RunJobExpectingSuccess is similar to RunJob but returns true when the task completes successfully.
func RunJobExpectingSuccess(jobInput *JobInput, startHTTPServer bool) bool {
	jobRunner := NewJobRunner(startHTTPServer)
	defer jobRunner.StopExecutor()

	jobResult := jobRunner.StartJob(jobInput)
	return jobResult.WaitForSuccess()
}

// RunJob runs a single Titus task based on provided JobInput
func RunJob(jobInput *JobInput, startHTTPServer bool) (string, error) {
	jobRunner := NewJobRunner(startHTTPServer)
	defer jobRunner.StopExecutor()

	jobResult := jobRunner.StartJob(jobInput)
	return jobResult.WaitForCompletion()
}

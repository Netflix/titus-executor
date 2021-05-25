package standalone

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/dockershellparser"
	titusdriver "github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/logger"
	metadataserverTypes "github.com/Netflix/titus-executor/metadataserver/types"
	podCommon "github.com/Netflix/titus-kube-common/pod"
	resourceCommon "github.com/Netflix/titus-kube-common/resource"
	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
	"gotest.tools/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var errStatusChannelClosed = errors.New("Status channel closed")

const (
	logUploadDir       = "/var/tmp/titus-executor/tests"
	logViewerTestImage = "titusoss/titus-logviewer@sha256:750a908c244c3f44b2b7abf1d9297aca859592e02736b3bd48aaebac022a87e5"
	metatronTestImage  = "titusoss/metatron@sha256:78b21578893c228d006000c03eaa2546c1b1976345b273d31f704823f12d5273"
	sshdTestImage      = "titusoss/titus-sshd@sha256:6f6f89250771a50e13d5a3559712defc256c37b144ca22e46c69f35f06d848a0"
	defaultAppName     = "myapp"
	defaultIamRole     = "arn:aws:iam::0:role/DefaultContainerRole"
	True               = "true"
)

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
	// SchedPolicy sets the scheduler policy (batch, idle)
	SchedPolicy string
	// CPUBursting sets the CPU bursting protobuf attribute
	CPUBursting bool
	// CPU sets the CPU count resource attribute
	CPU *int64
	// GPU sets the GPU count resource attribute
	GPU *int64
	// StopTimeoutSeconds is the duration we wait after SIGTERM for the container to exit
	KillWaitSeconds uint32
	// Tty attaches a tty to the container via a passthrough attribute
	Tty bool
	// LogViewerEnabled enables running with the logviewer system service container
	LogViewerEnabled bool
	// MetatronEnabled enables running with the metatron system service container
	MetatronEnabled bool
	// Mem sets the memory resource attribute in MiB
	Mem *int64
	// ShmSize sets the shared memory size of `/dev/shm` in MiB
	ShmSize *uint32
	// UsePodSpec tells the jobrunner to populate the pod spec rather than ContainerInfo
	UsePodSpec bool

	GPUManager runtimeTypes.GPUManager
}

// JobRunResponse returned from RunJob
type JobRunResponse struct {
	runner     *runner.Runner
	ctx        context.Context
	cancel     context.CancelFunc
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
	res := status == "TASK_FINISHED"
	if !res {
		jobRunResponse.logContainerStdErrOut()
	}

	return res
}

// WaitForFailure blocks on the jobs completion and returns true
// if it exits with a non-zero (user) error
func (jobRunResponse *JobRunResponse) WaitForFailure() bool {
	status, err := jobRunResponse.WaitForCompletion()
	if err != nil {
		return false
	}
	res := status == "TASK_FAILED"
	if !res {
		jobRunResponse.logContainerStdErrOut()
	}

	return res
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

// WaitForFailureStatus waits until a terminal state and returns the status
func (jobRunResponse *JobRunResponse) WaitForFailureStatus(ctx context.Context) (*runner.Update, error) {
	for {
		select {
		case status, ok := <-jobRunResponse.UpdateChan:
			if !ok {
				return nil, errors.New("UpdateChan closed before TASK_FAIL")
			}
			if !status.State.IsTerminalStatus() {
				continue
			}

			return &status, nil
		case <-ctx.Done():
			return nil, ctx.Err()
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

// logContainerStdErrOut logs the contents of the container's stderr / stdout
func (jobRunResponse *JobRunResponse) logContainerStdErrOut() {
	logNames := []string{
		"stderr",
		"stdout",
	}

	for _, l := range logNames {
		lp := fmt.Sprintf("%s/titan/mainvpc/logs/%s/%s", logUploadDir, jobRunResponse.TaskID, l)
		_, err := os.Stat(lp)
		if os.IsNotExist(err) {
			log.Infof("logContainerStdErrOut: file does not exist: %s", lp)
			continue
		}

		contents, err := ioutil.ReadFile(lp)
		if err != nil {
			log.WithError(err).Errorf("Error reading file '%s': %+v", lp, err)
			continue
		}

		log.Infof("logContainerStdErrOut: %s: '%s'", l, contents)
	}

}

// GenerateConfigs generates test configs
func GenerateConfigs(jobInput *JobInput) (*config.Config, *docker.Config) {
	configArgs := []string{"--copy-uploader", logUploadDir}

	logViewerEnabled := false
	metatronEnabled := false
	if jobInput != nil {
		if jobInput.LogViewerEnabled {
			logViewerEnabled = true
		}
		if jobInput.MetatronEnabled {
			metatronEnabled = true
		}
	}

	// GenerateConfiguration() doesn't actually update the config it generates based
	// on these flags: this is just to test command-line parsing
	configArgs = append(configArgs,
		"--container-logviewer", strconv.FormatBool(logViewerEnabled),
		"--logviewer-service-image", logViewerTestImage,
		"--metatron-enabled", strconv.FormatBool(metatronEnabled),
		"--metatron-service-image", metatronTestImage,
		"--container-sshd", True,
		"--sshd-service-image", sshdTestImage)

	cfg, err := config.GenerateConfiguration(configArgs)
	if err != nil {
		panic(err)
	}

	cfg.ContainerLogViewer = logViewerEnabled
	cfg.LogViewerServiceImage = logViewerTestImage
	cfg.MetatronEnabled = metatronEnabled
	cfg.MetatronServiceImage = metatronTestImage
	cfg.SSHDServiceImage = sshdTestImage

	if runtime.GOOS == "darwin" {
		// On darwin these don't work yet
		cfg.LogsTmpDir = "/tmp/titus-container-logs"
		// Assuming if you are on darwin, then pulling from a local netflix mirror
		// makes docker hub rate limiting errors go away
		cfg.DockerRegistry = "docker-hub.netflix.net"
		// during full docker-in-docker tests, the titus agent touches the default file
		// for darwin, we can just use /dev/null and it is fine, but it must be *some* file
		cfg.ContainerSSHDCAFile = "/dev/null"
	}

	// This ensures that under test we are using the tini that is part of our build,
	// regardless of our absolute path in the filesystem. This is particularly useful
	// for running tests on darwin, so that they can also use tini.
	cwd, _ := os.Getwd()
	dockerArgs := []string{"--titus.executor.tiniPath=" + cwd + "/../../build/bin/linux-amd64/tini-static"}

	dockerCfg, err := docker.GenerateConfiguration(dockerArgs)
	if err != nil {
		panic(err)
	}

	log.Infof("GenerateConfigs: configArgs=%+v, cfg=%+v, dockerCfg=%+v", configArgs, cfg, dockerCfg)
	return cfg, dockerCfg
}

var r = rand.New(rand.NewSource(999)) // nolint: gosec

// StopExecutor stops a currently running executor
func (jobRunResponse *JobRunResponse) StopExecutor() {
	jobRunResponse.StopExecutorAsync()
	<-jobRunResponse.runner.StoppedChan
}

// StopExecutorAsync stops a currently running executor
func (jobRunResponse *JobRunResponse) StopExecutorAsync() {
	jobRunResponse.cancel()
}

func createContainerInfoTask(jobInput *JobInput, jobID string, task *runner.Task, env map[string]string, resources *runtimeTypes.Resources) error {
	ci := &titus.ContainerInfo{
		ImageName: proto.String(jobInput.ImageName),
		Version:   proto.String(jobInput.Version),
		JobId:     proto.String(jobID),
		AppName:   proto.String("myapp"),
		NetworkConfigInfo: &titus.ContainerInfo_NetworkConfigInfo{
			EniLabel:  proto.String("1"),
			EniLablel: proto.String("1"), // deprecated, but protobuf marshaling raises an error if it's not present
		},
		IamProfile:       proto.String(defaultIamRole),
		Capabilities:     jobInput.Capabilities,
		TitusProvidedEnv: env,
		PassthroughAttributes: map[string]string{
			runtimeTypes.LogKeepLocalFileAfterUploadParam: True,
		},
	}

	if p := jobInput.Process; p != nil {
		ci.Process = &titus.ContainerInfo_Process{
			Entrypoint: p.Entrypoint,
			Command:    p.Cmd,
		}
	} else {
		ci.EntrypointStr = proto.String(jobInput.EntrypointOld) // nolint: staticcheck
	}
	if jobInput.SchedPolicy != "" {
		ci.Batch = proto.Bool(true)
	}
	if jobInput.SchedPolicy == "idle" {
		ci.PassthroughAttributes["titusParameter.agent.batchPriority"] = "idle"
	}
	if jobInput.ShmSize != nil {
		ci.ShmSizeMB = jobInput.ShmSize
	}
	if jobInput.Tty {
		ci.PassthroughAttributes["titusParameter.agent.ttyEnabled"] = True
	}

	if jobInput.MetatronEnabled {
		ci.MetatronCreds = &titus.ContainerInfo_MetatronCreds{
			AppMetadata: proto.String("fake-metatron-app"),
			MetadataSig: proto.String("fake-metatron-sig"),
		}
	}
	if jobInput.KillWaitSeconds > 0 {
		ci.KillWaitSeconds = proto.Uint32(jobInput.KillWaitSeconds)
	}
	if id := jobInput.ImageDigest; id != "" {
		ci.ImageDigest = proto.String(id)
	}

	ci.AllowCpuBursting = proto.Bool(jobInput.CPUBursting)
	task.TitusInfo = ci

	return nil
}

func createPodTask(jobInput *JobInput, jobID string, task *runner.Task, env map[string]string, resources *runtimeTypes.Resources, cfg *config.Config) error {
	image := cfg.DockerRegistry + "/" + jobInput.ImageName
	if jobInput.ImageDigest != "" {
		image = image + "@" + jobInput.ImageDigest
	} else {
		image = image + ":" + jobInput.Version
	}

	resourceReqs := runtimeTypes.ResourcesToPodResourceRequirements(resources)
	bandwidth := resourceReqs.Limits[resourceCommon.ResourceNameNetwork]
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      task.TaskID,
			Namespace: "default",
			Annotations: map[string]string{
				podCommon.AnnotationKeyPodSchemaVersion: "1",
				podCommon.AnnotationKeyIAMRole:          defaultIamRole,
				podCommon.AnnotationKeyEgressBandwidth:  bandwidth.String(),
				podCommon.AnnotationKeyIngressBandwidth: bandwidth.String(),
				podCommon.AnnotationKeyLogKeepLocalFile: True,
				podCommon.AnnotationKeyWorkloadName:     defaultAppName,
				podCommon.AnnotationKeyJobID:            jobID,
			},
			Labels: map[string]string{},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Env: []corev1.EnvVar{
						{
							// This needs to be set for the IMDS to start up
							Name:  runtimeTypes.TitusTaskInstanceIDKey,
							Value: task.TaskID,
						},
						{
							// This needs to be set for the logviewer to work properly
							Name:  "TITUS_TASK_ID",
							Value: task.TaskID,
						},
					},
					Name:      task.TaskID,
					Image:     image,
					Resources: resourceReqs,
				},
			},
		},
	}

	fc := &pod.Spec.Containers[0]
	pod.Annotations[podCommon.AnnotationKeyPodTitusUserEnvVarsStartIndex] = strconv.Itoa(len(fc.Env))

	if p := jobInput.Process; p != nil {
		fc.Command = p.Entrypoint
		fc.Args = p.Cmd
	} else {
		entrypoint, err := dockershellparser.ProcessWords(jobInput.EntrypointOld, []string{})
		if err != nil {
			return err
		}
		fc.Command = entrypoint
	}

	for k, v := range jobInput.Environment {
		fc.Env = append(fc.Env, corev1.EnvVar{Name: k, Value: v})
	}

	// capabilities
	if jobInput.Capabilities != nil {
		cp := corev1.Capabilities{}
		for _, add := range jobInput.Capabilities.GetAdd() {
			cp.Add = append(cp.Add, corev1.Capability(add.String()))
		}
		for _, drop := range jobInput.Capabilities.GetDrop() {
			cp.Drop = append(cp.Drop, corev1.Capability(drop.String()))
		}

		if len(cp.Add) > 0 || len(cp.Drop) > 0 {
			fc.SecurityContext = &corev1.SecurityContext{
				Capabilities: &cp,
			}
		}
	}

	if jobInput.SchedPolicy != "" {
		pod.Annotations[podCommon.AnnotationKeyPodSchedPolicy] = jobInput.SchedPolicy
	}

	if jobInput.ShmSize != nil {
		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
			MountPath: runtimeTypes.ShmMountPath,
			Name:      "dev-shm",
		})

		shmSize := resource.MustParse(fmt.Sprintf("%dMi", *jobInput.ShmSize))
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: "dev-shm",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					SizeLimit: &shmSize,
				},
			},
		})
	}

	if jobInput.Tty {
		pod.Spec.Containers[0].TTY = true
	}

	if jobInput.KillWaitSeconds > 0 {
		terminationGracePeriod := int64(jobInput.KillWaitSeconds)
		pod.Spec.TerminationGracePeriodSeconds = &terminationGracePeriod
	}

	if jobInput.CPUBursting {
		pod.Annotations[podCommon.AnnotationKeyPodCPUBurstingEnabled] = True
	}

	if jobInput.MetatronEnabled {
		pod.Annotations[podCommon.AnnotationKeySecurityWorkloadMetadata] = "fake-metatron-app"
		pod.Annotations[podCommon.AnnotationKeySecurityWorkloadMetadataSig] = "fake-metatron-sig"
	}

	task.Pod = pod

	return nil
}

// StartJob starts a job and returns once the job is started
func StartJob(t *testing.T, ctx context.Context, jobInput *JobInput) (*JobRunResponse, error) { // nolint: gocyclo,golint
	cfg, dockerCfg := GenerateConfigs(jobInput)

	log.SetLevel(log.DebugLevel)
	// Create an executor
	ctx, cancel := context.WithCancel(ctx) // nolint:govet
	// DO NOT CANCEL Context, this will stop the job.

	// Define some stock job to run
	var jobID string

	if jobInput.JobID == "" {
		jobID = fmt.Sprintf("Titus-%v%v", r.Intn(1000), time.Now().Second())
	} else {
		jobID = jobInput.JobID
	}

	ctx = logger.WithField(ctx, "jobID", jobID)
	// TODO: refactor this all to use NewContainer()
	// Strip out characters that aren't allowed in container names, and shorten
	// the name so that it only includes the name of the test
	validContainerNameRE := regexp.MustCompile("[^a-zA-Z0-9_.-]")
	shortTestNameRE := regexp.MustCompile(".*/")
	taskID := fmt.Sprintf("Titus-%v%v-%s-0-2", r.Intn(1000), time.Now().Second(), validContainerNameRE.ReplaceAllString(shortTestNameRE.ReplaceAllString(t.Name(), ""), "_"))
	ctx = logger.WithField(ctx, "taskID", taskID)

	env := map[string]string{
		"TITUS_TASK_ID":                       taskID,
		"TITUS_TASK_INSTANCE_ID":              taskID,
		metadataserverTypes.EC2IPv4EnvVarName: "1.2.3.4",
	}

	if jobInput.MetatronEnabled {
		env[metadataserverTypes.TitusMetatronVariableName] = True
	} else {
		env[metadataserverTypes.TitusMetatronVariableName] = "false"
	}

	// range over nil is safe
	for k, v := range jobInput.Environment {
		env[k] = v
	}
	cpu := int64(1)
	if jobInput.CPU != nil {
		cpu = *jobInput.CPU
	}
	memMiB := int64(400)
	if jobInput.Mem != nil {
		memMiB = *jobInput.Mem
	}
	gpu := int64(0)
	if jobInput.GPU != nil {
		gpu = *jobInput.GPU
	}
	diskMiB := int64(100)
	network := int64(128)
	resources := &runtimeTypes.Resources{
		Mem:     memMiB,
		CPU:     cpu,
		GPU:     gpu,
		Disk:    diskMiB,
		Network: network,
	}

	task := runner.Task{
		Mem:     memMiB,
		CPU:     cpu,
		Gpu:     gpu,
		Disk:    diskMiB,
		Network: network,
		TaskID:  taskID,
	}
	var tErr error

	if jobInput.UsePodSpec {
		tErr = createPodTask(jobInput, jobID, &task, env, resources, cfg)
	} else {
		tErr = createContainerInfoTask(jobInput, jobID, &task, env, resources)
	}
	if tErr != nil {
		cancel()
		return nil, fmt.Errorf("could not construct task: %w", tErr)
	}

	opts := []docker.Opt{}
	if jobInput.GPUManager == nil {
		opts = append(opts, docker.WithGPUManager(&dummyGPUManager{}))
	} else {
		opts = append(opts, docker.WithGPUManager(jobInput.GPUManager))
	}

	rp, err := docker.NewDockerRuntime(ctx, metrics.Discard, *dockerCfg, *cfg, opts...)
	assert.NilError(t, err)

	runner, err := runner.StartTaskWithRuntime(ctx, task, metrics.Discard, rp, *cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("Cannot start task / runner: %w", err)
	}

	jrr := &JobRunResponse{
		ctx:        ctx,
		cancel:     cancel,
		runner:     runner,
		TaskID:     taskID,
		UpdateChan: runner.UpdatesChan,
	}

	return jrr, nil
}

// KillTask issues a kill task request to the executor. The kill
// may be done in the background and the state change should occur
// on the existing JobRunResponse channel.
func (jobRunResponse *JobRunResponse) KillTask() error {
	jobRunResponse.runner.Kill()
	<-jobRunResponse.runner.StoppedChan
	return nil
}

// RunJobExpectingSuccess is similar to RunJob but returns true when the task completes successfully.
func RunJobExpectingSuccess(t *testing.T, jobInput *JobInput) bool {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobResult, err := StartJob(t, ctx, jobInput)
	assert.NilError(t, err)

	defer jobResult.StopExecutor()
	return jobResult.WaitForSuccess()
}

// RunJobExpectingFailure is similar to RunJob but returns true when the task completes successfully.
func RunJobExpectingFailure(t *testing.T, jobInput *JobInput) bool {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobResult, err := StartJob(t, ctx, jobInput)
	assert.NilError(t, err)

	defer jobResult.StopExecutor()
	return jobResult.WaitForFailure()
}

// RunJob runs a single Titus task based on provided JobInput
func RunJob(t *testing.T, jobInput *JobInput) (string, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobResult, err := StartJob(t, ctx, jobInput)
	assert.NilError(t, err)

	return jobResult.WaitForCompletion()
}

// StartJobExpectingFailure attempts to start a job, but expects it to fail in the prestart (validation) phase
func StartJobExpectingFailure(t *testing.T, jobInput *JobInput) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobResult, err := StartJob(t, ctx, jobInput)

	if jobResult != nil {
		defer jobResult.StopExecutor()
	}
	assert.Assert(t, err != nil)
	return err
}

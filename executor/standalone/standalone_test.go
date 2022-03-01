package standalone

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	titusdriver "github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	podCommon "github.com/Netflix/titus-kube-common/pod"
	dockerTypes "github.com/docker/docker/api/types" // nolint: staticcheck
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Verbose() {
		log.SetLevel(log.DebugLevel)
	}
	os.Exit(m.Run())
}

type testImage struct {
	name   string
	tag    string
	digest string
}

var (
	busybox = testImage{
		name: "titusoss/busybox",
		tag:  "1.33.1",
	}
	ubuntu = testImage{
		name: "titusoss/ubuntu",
		tag:  "20200923-1600889010",
	}
	// TODO: Determine how this got built, and add it to the auto image builders?
	byDigest = testImage{
		name:   "titusoss/by-digest",
		tag:    "latest",
		digest: "sha256:2fc24d2a383c452ffe1332a60f94c618f34ece3e400c0b30c8f943bd7aeec033",
	}
	bigImage = testImage{
		name: "titusoss/big-image",
		tag:  "20171025-1508900976",
	}
	noEntrypoint = testImage{
		name:   "titusoss/no-entrypoint",
		tag:    "20180501-1525157430",
		digest: "sha256:e0ca04b07a20070c946b7a8d429b51b49eeb2f2953152fea7b6953ddc195540c",
	}
	shellEntrypoint = testImage{
		name: "titusoss/shell-entrypoint",
		tag:  "latest",
	}
	ignoreSignals = testImage{
		name: "titusoss/ignore-signals",
		tag:  "20180711-1531353167",
	}
	pty = testImage{
		name: "titusoss/pty",
		tag:  "20180507-1525733149",
	}
	envLabel = testImage{
		name: "titusoss/ubuntu-env-label",
		tag:  "20180621-1529540359",
	}
	userSet = testImage{
		name: "titusoss/user-set",
		tag:  "20210524-1621898423",
	}
	systemdImage = testImage{
		name: "titusoss/ubuntu-systemd-bionic",
		tag:  "20181219-1545261266",
	}
)

const defaultFailureTimeout = time.Minute

func wrapTestStandalone(t *testing.T) {
	if testing.Short() {
		t.Skip("Standalone tests are not enabled! Activate with the -short=false cmdline flag")
	}
	t.Parallel()
}

func skipOnDarwinOrNoRoot(t *testing.T) {
	if runtime.GOOS == "darwin" { //nolint:goconst
		t.Skip("This test is not compatible with darwin or docker-for-mac")
	}
	currentUser, _ := user.Current()
	if currentUser.Username != "root" {
		t.Skip("This test must be run as root")
	}
}

func dockerImageRemove(t *testing.T, imgName string) {
	cfg, dockerCfg := GenerateTestConfigs(nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runtimeMaker, err := docker.NewDockerRuntime(ctx, metrics.Discard, *dockerCfg, *cfg)
	require.NoError(t, err, "Error creating docker runtime maker")

	rt, err := runtimeMaker(ctx, nil, time.Time{})
	require.NoError(t, err, "Error creating docker runtime")

	drt, ok := rt.(*docker.DockerRuntime)
	require.True(t, ok, "DockerRuntime cast should succeed")

	require.True(t, ok, "DockerRuntime cast should succeed")
	err = drt.DockerImageRemove(ctx, imgName)
	require.NoErrorf(t, err, "No error removing docker image %s: +%v", imgName, err)
}

func dockerPull(t *testing.T, imgName string, imgDigest string) (*dockerTypes.ImageInspect, error) {
	cfg, dockerCfg := GenerateTestConfigs(nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runtimeMaker, err := docker.NewDockerRuntime(ctx, metrics.Discard, *dockerCfg, *cfg)
	require.NoError(t, err, "Error creating docker runtime maker")

	rt, err := runtimeMaker(ctx, nil, time.Time{})
	require.NoError(t, err, "Error creating docker runtime")

	drt, ok := rt.(*docker.DockerRuntime)
	require.True(t, ok, "DockerRuntime cast should succeed")
	pod, conf, err := runtimeTypes.PodContainerTestArgs()
	assert.NoError(t, err)
	pod.Spec.Containers[0].Image = imgName + "@" + imgDigest

	c, err := runtimeTypes.NewPodContainer(pod, *conf)
	assert.NoError(t, err)

	res, err := drt.DockerPull(ctx, c)
	require.NoError(t, err, "No error doing a docker pull")

	return res, err
}

func TestSimpleJob(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     busybox.name,
		Version:       busybox.tag,
		EntrypointOld: "echo Hello Titus",
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestSimpleJobWithBadEnvironment(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     busybox.name,
		Version:       busybox.tag,
		EntrypointOld: "echo Hello Titus",
		Environment: map[string]string{
			"ksrouter.filter.xpath.expression": `(XXXXX("XXXXXX") = "XXXXXXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXXXXXXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXX", "XXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXX", "XXXXXXXXXXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXX" XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXXX" XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX"))`,
			"BAD":                              `"`,
			"AlsoBAD":                          "",
		},
		JobID: t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestCustomCmd(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName: busybox.name,
		Version:   busybox.tag,
		Process: &Process{
			Cmd: []string{"echo", "Hello Titus"},
		},
		JobID: t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestInvalidFlatStringAsCmd(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName: busybox.name,
		Version:   busybox.tag,
		Process: &Process{
			Cmd: []string{"echo Hello Titus"}, // this will exit with status 127 since there is no such binary
		},
		JobID: t.Name(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()
	jobResponse, err := StartTestTask(t, ctx, ji)
	require.NoError(t, err)
	if err := jobResponse.WaitForFailureWithStatus(ctx, 127); err != nil {
		t.Fatal(err)
	}
}

func TestEntrypointAndCmd(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName: busybox.name,
		Version:   busybox.tag,
		Process: &Process{
			Entrypoint: []string{"/bin/sh", "-c"},
			Cmd:        []string{"echo Hello Titus"},
		},
		JobID: t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestEntrypointAndCmdFromImage(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName: shellEntrypoint.name,
		Version:   shellEntrypoint.tag,
		Process:   &Process{
			// entrypoint and cmd baked into the image will exit with status 123
		},
		JobID: t.Name(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()
	jobResponse, err := StartTestTask(t, ctx, ji)
	require.NoError(t, err)
	if err := jobResponse.WaitForFailureWithStatus(ctx, 123); err != nil {
		t.Fatal(err)
	}
}

func TestOverrideCmdFromImage(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName: shellEntrypoint.name,
		Version:   shellEntrypoint.tag,
		Process: &Process{
			Cmd: []string{"exit 5"},
		},
		JobID: t.Name(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()
	jobResponse, err := StartTestTask(t, ctx, ji)
	require.NoError(t, err)
	if err := jobResponse.WaitForFailureWithStatus(ctx, 5); err != nil {
		t.Fatal(err)
	}
}

func TestResetEntrypointFromImage(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName: shellEntrypoint.name,
		Version:   shellEntrypoint.tag,
		Process: &Process{
			Entrypoint: []string{""},
			Cmd:        []string{"/bin/sh", "-c", "exit 6"},
		},
		JobID: t.Name(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()
	jobResponse, err := StartTestTask(t, ctx, ji)
	require.NoError(t, err)
	if err := jobResponse.WaitForFailureWithStatus(ctx, 6); err != nil {
		t.Fatal(err)
	}
}
func TestResetCmdFromImage(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName: shellEntrypoint.name,
		Version:   shellEntrypoint.tag,
		Process: &Process{
			Cmd: []string{""},
		},
		JobID: t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestNoCapPtraceByDefault(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: "/bin/sh -c '! (/sbin/capsh --print | tee /logs/no-ptrace.log | grep sys_ptrace')",
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestCanAddCapabilities(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: "/bin/sh -c '/sbin/capsh --print | tee /logs/ptrace.log | grep sys_ptrace'",
		Capabilities: &titus.ContainerInfo_Capabilities{
			Add: []titus.ContainerInfo_Capabilities_Capability{
				titus.ContainerInfo_Capabilities_SYS_PTRACE,
			},
		},
		JobID: t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

// ensure the default capability set matches what docker and rkt do:
// https://github.com/docker/docker/blob/master/oci/defaults_linux.go#L62-L77
// https://github.com/appc/spec/blob/master/spec/ace.md#linux-isolators
func TestDefaultCapabilities(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName: ubuntu.name,
		Version:   ubuntu.tag,
		// Older kernels (3.13 on jenkins) have a different bitmask, so we check both the new and old formats
		EntrypointOld: `/bin/bash -c 'cat /proc/self/status | tee /logs/capabilities.log | egrep "CapEff:\s+(00000020a80425fb|00000000a80425fb)"'`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestMakesPTY(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     pty.name,
		Version:       pty.tag,
		EntrypointOld: "/bin/bash -c '/usr/bin/unbuffer /usr/bin/tty | grep /dev/pts'",
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestStdoutGoesToLogFile(t *testing.T) {
	wrapTestStandalone(t)
	message := fmt.Sprintf("Some message with ID=%s, and a suffix.", uuid.New().String())
	cmd := fmt.Sprintf(`sh -c 'echo "%[1]s" && sleep 1 && grep "%[1]s" /logs/stdout'`, message)
	ji := &JobInput{
		ImageName:     busybox.name,
		Version:       busybox.tag,
		EntrypointOld: cmd,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestStderrGoesToLogFile(t *testing.T) {
	wrapTestStandalone(t)
	message := fmt.Sprintf("Some message with ID=%s, and a suffix.", uuid.New().String())
	cmd := fmt.Sprintf(`sh -c 'echo "%[1]s" >&2 && sleep 1 && grep "%[1]s" /logs/stderr'`, message)
	ji := &JobInput{
		ImageName:     busybox.name,
		Version:       busybox.tag,
		EntrypointOld: cmd,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestImageByDigest(t *testing.T) {
	wrapTestStandalone(t)
	cmd := `grep not-latest /etc/who-am-i`
	ji := &JobInput{
		ImageName:     byDigest.name,
		ImageDigest:   byDigest.digest,
		EntrypointOld: cmd,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestImageByDigestIgnoresTag(t *testing.T) {
	wrapTestStandalone(t)
	cmd := `grep not-latest /etc/who-am-i`
	ji := &JobInput{
		ImageName: byDigest.name,
		Version:   "20171024-1508896310", // should be ignored
		// This version (tag) of the image has the digest:
		// sha256:652d2dd17041cb520feae4de0a976df29af4cd1d002d19ec7c8d5204f8ab1518
		// and it doesn't have not-latest in /etc/who-am-i
		ImageDigest:   byDigest.digest,
		EntrypointOld: cmd,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestImageInvalidDigestFails(t *testing.T) {
	wrapTestStandalone(t)
	digest := "some-invalid-digest"
	ji := &JobInput{
		ImageName:     byDigest.name,
		Version:       "latest", // should be ignored
		ImageDigest:   digest,
		EntrypointOld: "/bin/true",
		JobID:         t.Name(),
	}
	// In the pods container implementation, the docker image format is checked before starting
	err := StartJobExpectingFailure(t, ji)
	assert.Error(t, err, "error parsing docker image")
}

func TestImageNonExistingDigestFails(t *testing.T) {
	wrapTestStandalone(t)
	digest := "sha256:12345123456c6f231ea3adc7960cc7f753ebb0099999999999999a9b4dfdfdcd"
	ji := &JobInput{
		ImageName:     byDigest.name,
		ImageDigest:   digest,
		EntrypointOld: "/bin/true",
		JobID:         t.Name(),
	}
	status, err := RunJob(t, ji)
	if err != nil {
		t.Fatal(err)
	}
	if status != titusdriver.Failed.String() {
		t.Fatalf("Expected status=FAILED, got: %s", status)
	}
}

func TestImagePullError(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     busybox.name,
		Version:       "purposelyDoesntExist",
		EntrypointOld: "/usr/bin/true",
		JobID:         t.Name(),
	}
	status, err := RunJob(t, ji)
	if err != nil {
		t.Fatal(err)
	}
	if status != titusdriver.Failed.String() {
		t.Fatalf("Expected status=FAILED, got: %s", status)
	}
}

func TestCancelPullBigImage(t *testing.T) { // nolint: gocyclo
	wrapTestStandalone(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobResponse, err := StartTestTask(t, ctx, &JobInput{
		JobID:     t.Name(),
		ImageName: bigImage.name,
		Version:   bigImage.tag,
	})

	require.NoError(t, err)

	select {
	case taskStatus := <-jobResponse.UpdateChan:
		if taskStatus.State.String() != titusdriver.Starting.String() {
			t.Fatal("Task never observed in TASK_STARTING, instead: ", taskStatus)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Spent too long waiting for task starting")
	}

	if err := jobResponse.KillTask(); err != nil {
		t.Fatal("Could not stop task: ", err)
	}
	timeOut := time.After(30 * time.Second)
	for {
		select {
		case taskStatus := <-jobResponse.UpdateChan:
			//		t.Log("Observed task status: ", taskStatus)
			if taskStatus.State == titusdriver.Running {
				t.Fatalf("Task %s started after killTask %v", jobResponse.TaskID, taskStatus)
			}
			if taskStatus.State == titusdriver.Killed || taskStatus.State == titusdriver.Lost {
				t.Logf("Task %s successfully terminated with status %s", jobResponse.TaskID, taskStatus.State.String())
				goto big_task_killed
			}
		case <-timeOut:
			t.Fatal("Cancel failed to stop job in time")
		}
	}
big_task_killed:
	// We do this here, otherwise  a stuck executor can prevent this from exiting.
	jobResponse.StopExecutor()
}

func TestBadEntrypoint(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     busybox.name,
		Version:       busybox.tag,
		EntrypointOld: "bad",
		JobID:         t.Name(),
	}
	// We expect this to fail
	if RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestNoEntrypoint(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName: noEntrypoint.name,
		Version:   noEntrypoint.tag,
	}
	// We expect this to fail
	if RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestCanWriteInLogsAndSubDirs(t *testing.T) {
	wrapTestStandalone(t)
	cmd := `sh -c "mkdir -p /logs/prana && echo begining > /logs/prana/prana.log && ` +
		`mv /logs/prana/prana.log /logs/prana/prana-2016.log && echo ending >> /logs/out"`
	ji := &JobInput{
		ImageName:     busybox.name,
		Version:       busybox.tag,
		EntrypointOld: cmd,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestShutdown(t *testing.T) {
	wrapTestStandalone(t)
	// This test changed from canceling the context to stop the container to calling killTask. The reason being
	// is that now we plumb through a single context from the test -> jobRunner -> runtime. This is useful for
	// things like tracing, but it makes it so that once the context is cancelled, we can no longer make calls
	// to the backend.
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()

	ji := &JobInput{
		ImageName:     busybox.name,
		Version:       busybox.tag,
		EntrypointOld: "sleep 6000",
		JobID:         t.Name(),
	}

	jobRunner, err := StartTestTask(t, ctx, ji)
	require.NoError(t, err)
	defer jobRunner.StopExecutor()

	var taskRunning bool
	for {
		select {
		case status := <-jobRunner.UpdateChan:
			if status.State == titusdriver.Running {
				if taskRunning == false {
					taskRunning = true
					t.Logf("Task is running, stopping executor")
					go func() {
						_ = jobRunner.KillTask()
					}()
				}
			}
			if status.State.IsTerminalStatus() {
				if status.State != titusdriver.Killed {
					t.Errorf("Task %s not killed successfully, %s!", jobRunner.TaskID, status.State.String())
				}
				if !taskRunning {
					t.Errorf("Task never went into running, and therefore killed for some other reason")
				}
				return
			}
		case <-ctx.Done():
			t.Errorf("Task %s did not reach RUNNING - timed out: %s", jobRunner.TaskID, ctx.Err().Error())
			return
		}
	}
}

func TestMetadataProxyInjection(t *testing.T) {
	wrapTestStandalone(t)
	// Doesn't work on darwin because we don't have systemd to launch the imds or any other system service
	skipOnDarwinOrNoRoot(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: "/bin/bash -c 'curl -sf http://169.254.169.254/latest/meta-data/local-ipv4 | grep 192.0.2.1'",
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestMetadataProxyFromLocalhost(t *testing.T) {
	wrapTestStandalone(t)
	// Doesn't work on darwin because we don't have systemd to launch the imds or any other system service
	skipOnDarwinOrNoRoot(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'curl -sf --interface 127.0.0.1 http://169.254.169.254/latest/meta-data/local-ipv4'`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestMetadataProxyOnIPv6(t *testing.T) {
	wrapTestStandalone(t)
	// Doesn't work on darwin because we don't have systemd to launch the imds or any other system service
	skipOnDarwinOrNoRoot(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'curl -sf http://[fd00:ec2::254]/latest/meta-data/local-ipv4'`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestMetadataProxyPublicIP(t *testing.T) {
	wrapTestStandalone(t)
	// Doesn't work on darwin because we don't have systemd to launch the imds or any other system service
	skipOnDarwinOrNoRoot(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: "/bin/bash -c 'curl -sf http://169.254.169.254/latest/meta-data/public-ipv4 | grep 203.0.113.11",
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testTerminateTimeoutWrapped(t *testing.T, jobID string, killWaitSeconds uint32) (*runner.Update, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()

	// Submit a job that runs for a long time and does
	// NOT exit on SIGTERM
	ji := &JobInput{
		ImageName:       ignoreSignals.name,
		Version:         ignoreSignals.tag,
		KillWaitSeconds: killWaitSeconds,
		JobID:           t.Name(),
	}
	// Start the executor
	jobResponse, err := StartTestTask(t, ctx, ji)
	require.NoError(t, err)
	defer jobResponse.StopExecutorAsync()

	// Wait until the task is running
	for status := range jobResponse.UpdateChan {
		if status.State.IsTerminalStatus() {
			t.Fatal("Task exited prematurely (before becoming healthy)")
		}
		log.Infof("Received status update %+v", status)
		if status.State.String() == titusdriver.Running.String() && strings.Contains(status.Mesg, "health_status: healthy") {
			break
		}
	}

	// Submit a request to kill the job. Since the
	// job does not exit on SIGTERM we expect the kill
	// to take at least some seconds
	killTime := time.Now()
	if err := jobResponse.KillTask(); err != nil {
		t.Fail()
	}

	for status := range jobResponse.UpdateChan {
		if status.State.IsTerminalStatus() {
			killTime := time.Since(killTime)
			// this is a terminal state, so it's okay to return a reference to a loop iterator
			return &status, killTime // nolint: scopelint
		}
	}

	t.Fail()
	return nil, 0
}

func TestTerminateTimeout(t *testing.T) {
	wrapTestStandalone(t)
	status, killTime := testTerminateTimeoutWrapped(t, t.Name(), 15)
	if status.State != titusdriver.Killed {
		t.Fail()
	}
	if killTime < time.Second*time.Duration(15) {
		t.Fatalf("Task was killed too quickly, in %s", killTime.String())
	}
}

func TestTerminateTimeoutNotTooSlow(t *testing.T) {
	wrapTestStandalone(t)
	status, killTime := testTerminateTimeoutWrapped(t, t.Name(), 15)
	if status.State != titusdriver.Killed {
		t.Fail()
	}
	// 45 is 15 with some buffer?
	if killTime > time.Second*time.Duration(45) {
		t.Fatalf("Task wasn't killed quickly enough, in %s", killTime.String())
	}
}

func TestOOMAdj(t *testing.T) {
	wrapTestStandalone(t)
	// Doesn't work on darwin because it assumes you can see /proc from the container
	skipOnDarwinOrNoRoot(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'cat /proc/1/oom_score | grep 999'`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestOOMKill(t *testing.T) {
	wrapTestStandalone(t)
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()

	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `stress --vm 100 --vm-keep --vm-hang 100`,
		JobID:         t.Name(),
	}

	// Start the executor
	jobResponse, err := StartTestTask(t, ctx, ji)
	require.NoError(t, err)
	defer jobResponse.StopExecutorAsync()

	// Wait until the task is running
	for status := range jobResponse.UpdateChan {
		if status.State.IsTerminalStatus() {
			if status.State.String() != titusdriver.Failed.String() {
				t.Fail()
			}
			if !strings.Contains(status.Mesg, "OOMKilled") {
				t.Fatal("Task killed due to: ", status.Mesg)
			}
			return
		}
	}
	t.Fail()
}

func TestSchedBatch(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'schedtool 0 | grep SCHED_BATCH | grep 19'`,
		JobID:         t.Name(),
		SchedPolicy:   "batch",
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestSchedNormal(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'schedtool 0 | grep SCHED_NORMAL'`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestSchedIdle(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'schedtool 0 | grep SCHED_IDLE'`,
		JobID:         t.Name(),
		SchedPolicy:   "idle",
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestNewEnvironmentLocationPositive(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     envLabel.name,
		Version:       envLabel.tag,
		EntrypointOld: `cat /etc/nflx/base-environment.d/200titus`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestNewEnvironmentLocationNegative(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     envLabel.name,
		Version:       envLabel.tag,
		EntrypointOld: `cat /etc/profile.d/netflix_environment.sh`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingFailure(t, ji) {
		t.Fail()
	}
}

func TestOldEnvironmentLocationPositive(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `cat /etc/profile.d/netflix_environment.sh`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}
func TestOldEnvironmentLocationNegative(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `cat /etc/nflx/base-environment.d/200titus`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingFailure(t, ji) {
		t.Fail()
	}
}

func TestNoCPUBursting(t *testing.T) {
	wrapTestStandalone(t)
	// Not sure exactly why this doesn't work on darwin, cfs_quota_us isn't in there
	skipOnDarwinOrNoRoot(t)
	ji := &JobInput{
		ImageName: ubuntu.name,
		Version:   ubuntu.tag,
		// Make sure quota is set
		EntrypointOld: `/bin/bash -c 'cat /sys/fs/cgroup/cpuacct/cpu.cfs_quota_us|grep -v - -1'`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestCPUBursting(t *testing.T) {
	wrapTestStandalone(t)
	// Not sure exactly why this doesn't work on darwin, cfs_quota_us isn't in there
	skipOnDarwinOrNoRoot(t)
	ji := &JobInput{
		ImageName: ubuntu.name,
		Version:   ubuntu.tag,
		// Make sure quota is set
		EntrypointOld: `/bin/bash -c 'cat /sys/fs/cgroup/cpuacct/cpu.cfs_quota_us|grep - -1'`,
		JobID:         t.Name(),
		CPUBursting:   true,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestTwoCPUs(t *testing.T) {
	wrapTestStandalone(t)
	// Not sure exactly why this doesn't work on darwin, cpus.shares isn't there
	skipOnDarwinOrNoRoot(t)
	var cpuCount int64 = 2
	ji := &JobInput{
		ImageName: ubuntu.name,
		Version:   ubuntu.tag,
		// Make sure quota is set
		EntrypointOld: `/bin/bash -c 'cat /sys/fs/cgroup/cpuacct/cpu.shares|grep 200'`,
		JobID:         t.Name(),
		CPU:           &cpuCount,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestTty(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/usr/bin/tty`,
		JobID:         t.Name(),
		Tty:           true,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestTtyNegative(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/usr/bin/tty`,
		JobID:         t.Name(),
		// Tty not specified
	}
	if !RunJobExpectingFailure(t, ji) {
		t.Fail()
	}
}

func TestCachedDockerPull(t *testing.T) {
	wrapTestStandalone(t)
	// The no entrypoint image should never be in use by any running
	// containers, so it should be safe to delete
	dockerImageRemove(t, noEntrypoint.name+"@"+noEntrypoint.digest)
	res, err := dockerPull(t, noEntrypoint.name, noEntrypoint.digest)
	require.NoError(t, err, "No error from first docker pull")

	assert.Nil(t, res, "image shouldn't be cached")

	res, err = dockerPull(t, noEntrypoint.name, noEntrypoint.digest)
	require.NoError(t, err, "No error from second docker pull")

	// Note: even when wrong, the res object is not strictly nil
	// This assertion never catches anything
	assert.NotNil(t, res, "image should now be cached")
	// Should be at least one digest.
	assert.GreaterOrEqual(t, len(res.RepoDigests), 1, "digest should be present")
	expectedUnqualifiedImage := noEntrypoint.name + "@" + noEntrypoint.digest
	actualFulllyQualifiedImage := res.RepoDigests[0]
	// We don't care about the registry part at the beginning, but we care that the
	// image with digest is in the full image name
	assert.Contains(t, actualFulllyQualifiedImage, expectedUnqualifiedImage, "Correct digest should be returned")
}

func TestMetatron(t *testing.T) {
	wrapTestStandalone(t)
	// Doesn't work on darwin because it need system stuff
	skipOnDarwinOrNoRoot(t)
	ji := &JobInput{
		ImageName:       userSet.name,
		Version:         userSet.tag,
		MetatronEnabled: true,
		// The metatron test image writes out the task identity retrieved from the metadata service to `/task-identity`
		EntrypointOld: strings.Join([]string{
			"/bin/bash -c \"",
			"echo '-- task identity: begin --' ;",
			"curl -isSH Accept:application/json http://169.254.169.254/nflx/v1/task-identity ;",
			"echo '-- task identity: end --' ;",
			"cat /task-identity ;",
			"grep " + t.Name() + " /task-identity &&",
			"grep jobAcceptedTimestampMs /task-identity | grep -E '[\\d+]'",
			"\"",
		}, " "),
		JobID: t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

// Test that we return failure messages from services
func TestMetatronFailure(t *testing.T) {
	wrapTestStandalone(t)
	// Doesn't work on darwin because it need systemd stuff
	skipOnDarwinOrNoRoot(t)
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()

	ji := &JobInput{
		ImageName:       userSet.name,
		Version:         userSet.tag,
		MetatronEnabled: true,
		// We should never get to running this, since we're expecting the metatron service to fail before the entrypoint can run
		EntrypointOld: "grep " + t.Name() + " /task-identity",
		Environment: map[string]string{
			// Setting this env var causes the test metatron image to fail with the message "initialization failed"
			"TITUS_TEST_FAIL_METATRON_INIT": "true",
		},
		JobID: t.Name(),
	}

	jobResponse, err := StartTestTask(t, ctx, ji)
	require.NoError(t, err)
	defer jobResponse.StopExecutor()

	status, err := jobResponse.WaitForFailureStatus(ctx)
	assert.Nil(t, err)
	assert.NotNil(t, status)
	if status != nil {
		assert.Equal(t, "container prestart error: error starting titus-sidecar-metatron-sync service: initialization failed: exit status 1", status.Mesg)
	}
}

// Test that `/run` is a tmpfs mount, and has the default size
func TestRunTmpFsMount(t *testing.T) {
	wrapTestStandalone(t)
	var mem int64 = 256
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		Mem:           &mem,
		EntrypointOld: `/bin/bash -c 'findmnt -l -t tmpfs -o target,size | grep -e "/run[^/]" | grep 128M'`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

// Test that we can execute files in `/run`
func TestExecSlashRun(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'cp /bin/ls /run/ && /run/ls'`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

// Test for a container running a systemd labeled image that `/run/lock` is a tmpfs mount, and has the default size
func TestSystemdImageMount(t *testing.T) {
	wrapTestStandalone(t)
	var mem int64 = 256
	ji := &JobInput{
		ImageName:     systemdImage.name,
		Version:       systemdImage.tag,
		Mem:           &mem,
		EntrypointOld: `/bin/bash -c 'findmnt -l -t tmpfs -o target,size | grep -e "/run/lock[^/]" | grep 5M'`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

// Test that the size of `/dev/shm` can be set
func TestShm(t *testing.T) {
	wrapTestStandalone(t)
	var mem int64 = 256
	var shmSize uint32 = 192
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		Mem:           &mem,
		ShmSize:       &shmSize,
		EntrypointOld: `/bin/bash -c 'df | grep -e '^shm' | grep 196608'`,
		JobID:         t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestContainerLogViewer(t *testing.T) {
	wrapTestStandalone(t)
	// Doesn't work on darwin because it need systemd stuff
	skipOnDarwinOrNoRoot(t)
	ji := &JobInput{
		ImageName:        ubuntu.name,
		Version:          ubuntu.tag,
		LogViewerEnabled: true,
		EntrypointOld: "/bin/bash -c '" +
			"echo stdout-should-go-to-log;" +
			"source /etc/profile.d/netflix_environment.sh;" +
			"i=0;" +
			"url=\"http://localhost:8004/logs/${TITUS_TASK_INSTANCE_ID}?f=stdout\"; " +
			"while [[ $i -lt 10 ]] && ! curl -s $url | grep -q stdout-should-go-to-log ; do " +
			"  sleep 1;" +
			"  echo $i;" +
			"  ((i++));" +
			"done; " +
			"curl -Is $url;" +
			"curl -sf $url | grep -q stdout-should-go-to-log" +
			"'",
		JobID: t.Name(),
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestNegativeSeccomp(t *testing.T) {
	wrapTestStandalone(t)
	ji := &JobInput{
		ImageName: ubuntu.name,
		Version:   ubuntu.tag,
		// Make sure that the process exits due to timeout, and not due to permission denied error
		EntrypointOld: "/usr/bin/negative-seccomp",
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestGPUManager1GPU(t *testing.T) {
	wrapTestStandalone(t)
	// Doesn't work on darwin docker-for-mac won't accept alt docker runtimes
	skipOnDarwinOrNoRoot(t)
	g := &gpuManager{}
	var gpu int64 = 1

	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: fmt.Sprintf(`/bin/bash -c 'test "${TITUS_OCI_RUNTIME}" == "%s"'`, gpuTestRuntime),
		JobID:         t.Name(),
		GPUManager:    g,
		GPU:           &gpu,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()

	jobResult, err := StartTestTask(t, ctx, ji)
	assert.Nil(t, err)

	require.True(t, jobResult.WaitForSuccess())

	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}

	jobResult.StopExecutor()

	assert.Equal(t, 1, g.devicesAllocated)
	assert.Equal(t, 1, g.devicesDeallocated)
}

func TestBasicMultiContainer(t *testing.T) {
	wrapTestStandalone(t)

	// And for the main container, we use pgrep to ensure that our sentinel container
	// is in fact running along side us.
	testEntrypointOld := "pgrep -fx '/bin/sleep 420'"
	// The main container and the user-sentinel are both 'user' containers,
	// So we want the main container to waid just a little bit for the user-sentinel
	testEntrypointOld = `/bin/sh -c "sleep 3;` + testEntrypointOld + `"`

	ji := &JobInput{
		ImageName: busybox.name,
		Version:   busybox.tag,
		// This sentinel container is a second process we can look out
		// for, in order to detect if multi-container workloads are setup
		ExtraContainers: []corev1.Container{
			{
				Name:    "sleep-sentinel",
				Image:   busybox.name + `:` + busybox.tag,
				Command: []string{"/bin/sh", "-c"},
				Args:    []string{"/bin/sleep 420"},
			},
		},
		EntrypointOld: testEntrypointOld,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestBasicMultiContainerSharesCommonVolumes(t *testing.T) {
	wrapTestStandalone(t)

	// And for the main container, we use pgrep to ensure that our sentinel container
	// is in fact running along side us, and we can see shared files
	testEntrypointOld := "if ! ls -l /logs/sentinel; then exit 2; fi; if ! ls -l /run-shared/sentinel; then exit 3; fi"
	// The main container and the user-sentinel are both 'user' containers,
	// So we want the main container to waid just a little bit for the touch-sentinel
	testEntrypointOld = `/bin/sh -vxc "sleep 3;` + testEntrypointOld + `"`

	ji := &JobInput{
		ImageName: busybox.name,
		Version:   busybox.tag,
		// This sentinel container is a second process we can look out
		// for, in order to detect if multi-container workloads are setup
		ExtraContainers: []corev1.Container{
			{
				Name:    "touch-sentinel",
				Image:   busybox.name + `:` + busybox.tag,
				Command: []string{"/bin/sh", "-vxc"},
				Args:    []string{"touch /logs/sentinel && touch /run-shared/sentinel"},
			},
		},
		EntrypointOld: testEntrypointOld,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestBasicMultiContainerCustomSharedVolumes(t *testing.T) {
	wrapTestStandalone(t)

	// In the main container, we expect to see a file created by our sentinel
	testEntrypointOld := "stat /data2/sentinel"
	testEntrypointOld = `/bin/sh -vxc "sleep 3;` + testEntrypointOld + `"`

	sharedVolume := corev1.Volume{
		Name: "shared-from-mains-data2",
		VolumeSource: corev1.VolumeSource{
			FlexVolume: &corev1.FlexVolumeSource{
				Driver: "SharedContainerVolumeSource",
				Options: map[string]string{
					"sourcePath":      "/data2",
					"sourceContainer": "main",
				},
			},
		},
	}
	mountProp := corev1.MountPropagationNone
	sharedVolumeMount := corev1.VolumeMount{
		Name:             "shared-from-mains-data2",
		MountPath:        "/mains-data2",
		ReadOnly:         false,
		MountPropagation: &mountProp,
	}
	ji := &JobInput{
		ImageName: busybox.name,
		Version:   busybox.tag,
		// This sentinel container touches a file, and the main container should
		// see it if volumes are working
		ExtraContainers: []corev1.Container{
			{
				Name:         "touch-sentinel",
				Image:        busybox.name + `:` + busybox.tag,
				Command:      []string{"/bin/sh", "-vxc"},
				Args:         []string{"touch /mains-data2/sentinel"},
				VolumeMounts: []corev1.VolumeMount{sharedVolumeMount},
			},
		},
		Volumes:       []corev1.Volume{sharedVolume},
		EntrypointOld: testEntrypointOld,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}
func TestOtherUserContaintainerFailsTask(t *testing.T) {
	wrapTestStandalone(t)
	testEntrypointOld := `/bin/sh -c "sleep 5"`
	ji := &JobInput{
		ImageName: busybox.name,
		Version:   busybox.tag,
		ExtraContainers: []corev1.Container{
			{
				// This exit container is purposely designed to exit with a sentinel code, 42
				// For user containers, if one dies, the whole task dies, and should not just go
				// limping along with only the one container running.
				Name:    "exit-sentinel",
				Image:   busybox.name + `:` + busybox.tag,
				Command: []string{"/bin/sh", "-c"},
				Args:    []string{"sleep 1s; exit 42"},
			},
		},
		EntrypointOld: testEntrypointOld,
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()
	jobResponse, err := StartTestTask(t, ctx, ji)
	require.NoError(t, err)
	// We need to look for 42, which is the exit code of the *other* container.
	if err := jobResponse.WaitForFailureWithStatus(ctx, 42); err != nil {
		t.Fatal(err)
	}
}

func TestMultiContainerDoesPlatformFirst(t *testing.T) {
	wrapTestStandalone(t)

	// And for the main container, we use pgrep to ensure that our *user* sentinel container
	// is in fact running along side us.
	// It will only work if the user sentinel sidecar is seen running by the time we start.
	testEntrypointOld := "pgrep -fx '/bin/sleep 430'"
	// The main container and the user-sentinel are both 'user' containers,
	// So we want the main container to wait just a little bit for the user-sentinel
	// to come up, report back if the platform-sentinel is running or not, and then continue
	testEntrypointOld = `/bin/sh -c "sleep 6;` + testEntrypointOld + `"`
	ji := &JobInput{
		ImageName: busybox.name,
		Version:   busybox.tag,
		// This sentinel container is a second process we can look out
		// for, in order to detect if multi-container workloads are setup
		ExtraContainers: []corev1.Container{
			// This first one is a platform sidecar with a special sleep, this
			// *should* run first if the code is correct.
			{
				Name:    "platform-sentinel",
				Image:   busybox.name + `:` + busybox.tag,
				Command: []string{"/bin/sh", "-c"},
				Args:    []string{"/bin/sleep 420"},
			},
			// Second is a user sidecar, it *should* run second. If it sees the platform-sentinel
			// running, only then will it keep running with its own sleep
			{
				Name:    "user-sentinel",
				Image:   busybox.name + `:` + busybox.tag,
				Command: []string{"/bin/sh", "-c"},
				Args:    []string{"pgrep -fx '/bin/sleep 420' && /bin/sleep 430"},
			},
		},
		ExtraAnnotations: map[string]string{
			podCommon.ContainerAnnotation("platform-sentinel", podCommon.AnnotationKeySuffixContainersSidecar): "foo",
		},
		EntrypointOld: testEntrypointOld,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestBasicMultiContainerFailingHealthcheck(t *testing.T) {
	wrapTestStandalone(t)
	testEntrypointOld := `/bin/sleep 10`
	badHealthcheckCommand := corev1.ExecAction{
		Command: []string{"/bin/false"},
	}

	ji := &JobInput{
		ImageName: busybox.name,
		Version:   busybox.tag,
		ExtraContainers: []corev1.Container{
			{
				Name:    "failing-sidecar",
				Image:   busybox.name + `:` + busybox.tag,
				Command: []string{"/bin/sh", "-c"},
				Args:    []string{"/bin/sleep 600"},
				LivenessProbe: &corev1.Probe{
					Handler: corev1.Handler{
						Exec: &badHealthcheckCommand,
					},
					TimeoutSeconds:   1,
					PeriodSeconds:    1,
					FailureThreshold: 1,
				},
			},
		},
		EntrypointOld: testEntrypointOld,
	}
	// TODO: This doesn't fail yet because we don't stream docker events from sidecars
	// Or any way to see their health currently for that matter except via the update channel
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func TestPreStopHookRunsFirst(t *testing.T) {
	wrapTestStandalone(t)
	testEntrypointOld := `/bin/sleep 30`
	preStopCommand := corev1.ExecAction{
		Command: []string{"/bin/sh", "-c", "echo 'this should end up in the prestop output log'; exit 42"},
	}
	ji := &JobInput{
		ImageName:                busybox.name,
		Version:                  busybox.tag,
		EntrypointOld:            testEntrypointOld,
		mainContainerPreStopHook: &preStopCommand,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jobResponse, err := StartTestTask(t, ctx, ji)
	require.NoError(t, err)

	select {
	case taskStatus := <-jobResponse.UpdateChan:
		if taskStatus.State.String() != titusdriver.Starting.String() {
			t.Fatal("Task never observed in TASK_STARTING, instead: ", taskStatus)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Spent too long waiting for task starting")
	}

	timeOut := time.After(30 * time.Second)
	select {
	case taskStatus := <-jobResponse.UpdateChan:
		if taskStatus.State == titusdriver.Running {
			t.Log("Test task has started, ready to try issuing KillTask")
			if err := jobResponse.KillTask(); err != nil {
				t.Fatal("Could not stop task: ", err)
			}
		}
		if taskStatus.State == titusdriver.Killed || taskStatus.State == titusdriver.Lost {
			t.Logf("Task %s successfully terminated with status %s", jobResponse.TaskID, taskStatus.State.String())
			break
		}
	case <-timeOut:
		t.Fatal("Cancel failed to stop job in time")
	}
	jobResponse.StopExecutor()
	// There is no great way to assert that the preStop hook actually ran (at least, it didn't crash titus-executor)
	// If one needs proof, however, you can run this test in verbose mode, something like:
	// go test -v -timeout 30s -tags noroot -run ^TestPreStopHookRunsFirst$ github.com/Netflix/titus-executor/executor/standalone
	// And look to see the log message about its return code (should be 42), and you can
	// see the prestart .err and .out files in /logs/
}

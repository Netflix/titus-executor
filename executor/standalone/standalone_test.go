package standalone

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	titusdriver "github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	dockerTypes "github.com/docker/docker/api/types"
	protobuf "github.com/golang/protobuf/proto" // nolint: staticcheck
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	TASK_FAILED = "TASK_FAILED" // nolint:golint
)

var standalone bool
var shouldUsePodspecInTest bool

func TestMain(m *testing.M) {
	if debug, err := strconv.ParseBool(os.Getenv("DEBUG")); err == nil && debug {
		log.SetLevel(log.DebugLevel)
	}
	flag.BoolVar(&standalone, "standalone", false, "Enable standalone tests")
	flag.BoolVar(&shouldUsePodspecInTest, "shouldUsePodspecInTest", false, "Use pod schema v1 instead of cinfo in tests")
	flag.Parse()
	os.Exit(m.Run())
}

type testImage struct {
	name   string
	tag    string
	digest string
}

var (
	// TODO: Determine how this got built, and add it to the auto image builders?
	alpine = testImage{
		name: "titusoss/alpine",
		tag:  "3.5",
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
		tag:  "20190209-1549676483",
	}
	systemdImage = testImage{
		name: "titusoss/ubuntu-systemd-bionic",
		tag:  "20181219-1545261266",
	}
)

const defaultFailureTimeout = time.Minute

// returns the title-cased test name for a given test function
func funcToTestName(fun func(*testing.T, string)) string {
	fullName := runtime.FuncForPC(reflect.ValueOf(fun).Pointer()).Name()
	splitName := strings.Split(fullName, ".")
	funName := splitName[len(splitName)-1]
	suffix := ""
	if shouldUsePodspecInTest {
		suffix = "WithPod"
	} else {
		suffix = "WithCInfo"
	}
	return strings.Title(funName) + suffix
}

// This file still uses log as opposed to using the testing library's built-in logging framework.
// Since we do not configure Logrus, we will just log to stderr.
func TestStandalone(t *testing.T) {
	testFunctions := []func(*testing.T, string){
		testSimpleJob,
		testSimpleJobWithBadEnvironment,
		testCustomCmd,
		testInvalidFlatStringAsCmd,
		testEntrypointAndCmd,
		testEntrypointAndCmdFromImage,
		testOverrideCmdFromImage,
		testResetEntrypointFromImage,
		testResetCmdFromImage,
		testNoCapPtraceByDefault,
		testCanAddCapabilities,
		testDefaultCapabilities,
		testStdoutGoesToLogFile,
		testStderrGoesToLogFile,
		testImageByDigest,
		testImageByDigestIgnoresTag,
		testImageInvalidDigestFails,
		testImageNonExistingDigestFails,
		testImagePullError,
		testBadEntrypoint,
		testNoEntrypoint,
		testCanWriteInLogsAndSubDirs,
		testShutdown,
		testCancelPullBigImage,
		testMetadataProxyInjection,
		testMetadataProxyFromLocalhost,
		testMetadataProxyOnIPv6,
		testMetadataProxyPublicIP,
		testTerminateTimeout,
		testMakesPTY,
		testTerminateTimeoutNotTooSlow,
		testOOMAdj,
		testOOMKill,
		testSchedBatch,
		testSchedNormal,
		testSchedIdle,
		testNewEnvironmentLocationPositive,
		testNewEnvironmentLocationNegative,
		testOldEnvironmentLocationPositive,
		testOldEnvironmentLocationNegative,
		testNoCPUBursting,
		testCPUBursting,
		testTwoCPUs,
		testTty,
		testTtyNegative,
		testCachedDockerPull,
		testMetatron,
		testMetatronFailure,
		testRunTmpFsMount,
		testExecSlashRun,
		testSystemdImageMount,
		testShm,
		testContainerLogViewer,
		testnc,
		testGPUManager1GPU,
	}

	for _, fun := range testFunctions {
		testName := funcToTestName(fun)
		t.Run(testName, wrapTestStandalone(makeTestParallel(addImageNameToTest(fun, testName))))
	}
}

func makeTestParallel(f func(*testing.T)) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		f(t)
	}
}

func wrapTestStandalone(f func(*testing.T)) func(*testing.T) {
	return func(t *testing.T) {
		// TODO: Add logic to pull in config.flags, and docker.flags
		if !standalone {
			t.Skip("Standalone tests are not enabled! Activate with the -standalone cmdline flag")
		}
		f(t)
	}
}

func addImageNameToTest(f func(*testing.T, string), funTitle string) func(*testing.T) {
	return func(t *testing.T) {
		jobID := fmt.Sprintf("%s-%d-%d", funTitle, rand.Intn(1000), time.Now().Second()) // nolint: gosec
		f(t, jobID)
	}
}

func dockerImageRemove(t *testing.T, imgName string) {
	cfg, dockerCfg := GenerateConfigs(nil)

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
	cfg, dockerCfg := GenerateConfigs(nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runtimeMaker, err := docker.NewDockerRuntime(ctx, metrics.Discard, *dockerCfg, *cfg)
	require.NoError(t, err, "Error creating docker runtime maker")

	rt, err := runtimeMaker(ctx, nil, time.Time{})
	require.NoError(t, err, "Error creating docker runtime")

	drt, ok := rt.(*docker.DockerRuntime)
	require.True(t, ok, "DockerRuntime cast should succeed")
	taskID, titusInfo, resources, _, conf, err := runtimeTypes.ContainerTestArgs()
	assert.NoError(t, err)
	titusInfo.ImageName = protobuf.String(imgName)
	titusInfo.ImageDigest = protobuf.String(imgDigest)
	titusInfo.IamProfile = protobuf.String("arn:aws:iam::0:role/DefaultContainerRole")

	c, err := runtimeTypes.NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)

	res, err := drt.DockerPull(ctx, c)
	require.NoError(t, err, "No error doing a docker pull")

	return res, err
}

func testSimpleJob(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     alpine.name,
		Version:       alpine.tag,
		EntrypointOld: "echo Hello Titus",
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testSimpleJobWithBadEnvironment(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     alpine.name,
		Version:       alpine.tag,
		EntrypointOld: "echo Hello Titus",
		Environment: map[string]string{
			"ksrouter.filter.xpath.expression": `(XXXXX("XXXXXX") = "XXXXXXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXXXXXXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXX", "XXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXX", "XXXXXXXXXXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXX" XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXXX" XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX"))`,
			"BAD":                              `"`,
			"AlsoBAD":                          "",
		},
		JobID:      jobID,
		UsePodSpec: shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testCustomCmd(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName: alpine.name,
		Version:   alpine.tag,
		Process: &Process{
			Cmd: []string{"echo", "Hello Titus"},
		},
		JobID:      jobID,
		UsePodSpec: shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testInvalidFlatStringAsCmd(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName: alpine.name,
		Version:   alpine.tag,
		Process: &Process{
			Cmd: []string{"echo Hello Titus"}, // this will exit with status 127 since there is no such binary
		},
		JobID:      jobID,
		UsePodSpec: shouldUsePodspecInTest,
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()
	jobResponse, err := StartJob(t, ctx, ji)
	require.NoError(t, err)
	if err := jobResponse.WaitForFailureWithStatus(ctx, 127); err != nil {
		t.Fatal(err)
	}
}

func testEntrypointAndCmd(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName: alpine.name,
		Version:   alpine.tag,
		Process: &Process{
			Entrypoint: []string{"/bin/sh", "-c"},
			Cmd:        []string{"echo Hello Titus"},
		},
		JobID:      jobID,
		UsePodSpec: shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testEntrypointAndCmdFromImage(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName: shellEntrypoint.name,
		Version:   shellEntrypoint.tag,
		Process:   &Process{
			// entrypoint and cmd baked into the image will exit with status 123
		},
		JobID:      jobID,
		UsePodSpec: shouldUsePodspecInTest,
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()
	jobResponse, err := StartJob(t, ctx, ji)
	require.NoError(t, err)
	if err := jobResponse.WaitForFailureWithStatus(ctx, 123); err != nil {
		t.Fatal(err)
	}
}

func testOverrideCmdFromImage(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName: shellEntrypoint.name,
		Version:   shellEntrypoint.tag,
		Process: &Process{
			Cmd: []string{"exit 5"},
		},
		JobID:      jobID,
		UsePodSpec: shouldUsePodspecInTest,
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()
	jobResponse, err := StartJob(t, ctx, ji)
	require.NoError(t, err)
	if err := jobResponse.WaitForFailureWithStatus(ctx, 5); err != nil {
		t.Fatal(err)
	}
}

func testResetEntrypointFromImage(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName: shellEntrypoint.name,
		Version:   shellEntrypoint.tag,
		Process: &Process{
			Entrypoint: []string{""},
			Cmd:        []string{"/bin/sh", "-c", "exit 6"},
		},
		JobID:      jobID,
		UsePodSpec: shouldUsePodspecInTest,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()
	jobResponse, err := StartJob(t, ctx, ji)
	require.NoError(t, err)
	if err := jobResponse.WaitForFailureWithStatus(ctx, 6); err != nil {
		t.Fatal(err)
	}
}
func testResetCmdFromImage(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName: shellEntrypoint.name,
		Version:   shellEntrypoint.tag,
		Process: &Process{
			Cmd: []string{""},
		},
		JobID:      jobID,
		UsePodSpec: shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testNoCapPtraceByDefault(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: "/bin/sh -c '! (/sbin/capsh --print | tee /logs/no-ptrace.log | grep sys_ptrace')",
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testCanAddCapabilities(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: "/bin/sh -c '/sbin/capsh --print | tee /logs/ptrace.log | grep sys_ptrace'",
		Capabilities: &titus.ContainerInfo_Capabilities{
			Add: []titus.ContainerInfo_Capabilities_Capability{
				titus.ContainerInfo_Capabilities_SYS_PTRACE,
			},
		},
		JobID:      jobID,
		UsePodSpec: shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

// ensure the default capability set matches what docker and rkt do:
// https://github.com/docker/docker/blob/master/oci/defaults_linux.go#L62-L77
// https://github.com/appc/spec/blob/master/spec/ace.md#linux-isolators
func testDefaultCapabilities(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName: ubuntu.name,
		Version:   ubuntu.tag,
		// Older kernels (3.13 on jenkins) have a different bitmask, so we check both the new and old formats
		EntrypointOld: `/bin/bash -c 'cat /proc/self/status | tee /logs/capabilities.log | egrep "CapEff:\s+(00000020a80425fb|00000000a80425fb)"'`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testMakesPTY(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     pty.name,
		Version:       pty.tag,
		EntrypointOld: "/bin/bash -c '/usr/bin/unbuffer /usr/bin/tty | grep /dev/pts'",
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testStdoutGoesToLogFile(t *testing.T, jobID string) {
	message := fmt.Sprintf("Some message with ID=%s, and a suffix.", uuid.New().String())
	cmd := fmt.Sprintf(`sh -c 'echo "%[1]s" && sleep 1 && grep "%[1]s" /logs/stdout'`, message)
	ji := &JobInput{
		ImageName:     alpine.name,
		Version:       alpine.tag,
		EntrypointOld: cmd,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testStderrGoesToLogFile(t *testing.T, jobID string) {
	message := fmt.Sprintf("Some message with ID=%s, and a suffix.", uuid.New().String())
	cmd := fmt.Sprintf(`sh -c 'echo "%[1]s" >&2 && sleep 1 && grep "%[1]s" /logs/stderr'`, message)
	ji := &JobInput{
		ImageName:     alpine.name,
		Version:       alpine.tag,
		EntrypointOld: cmd,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testImageByDigest(t *testing.T, jobID string) {
	cmd := `grep not-latest /etc/who-am-i`
	ji := &JobInput{
		ImageName:     byDigest.name,
		ImageDigest:   byDigest.digest,
		EntrypointOld: cmd,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testImageByDigestIgnoresTag(t *testing.T, jobID string) {
	cmd := `grep not-latest /etc/who-am-i`
	ji := &JobInput{
		ImageName: byDigest.name,
		Version:   "20171024-1508896310", // should be ignored
		// This version (tag) of the image has the digest:
		// sha256:652d2dd17041cb520feae4de0a976df29af4cd1d002d19ec7c8d5204f8ab1518
		// and it doesn't have not-latest in /etc/who-am-i
		ImageDigest:   byDigest.digest,
		EntrypointOld: cmd,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testImageInvalidDigestFails(t *testing.T, jobID string) {
	digest := "some-invalid-digest"
	ji := &JobInput{
		ImageName:     byDigest.name,
		Version:       "latest", // should be ignored
		ImageDigest:   digest,
		EntrypointOld: "/bin/true",
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if shouldUsePodspecInTest {
		// In the pods container implementation, the docker image format is checked before starting
		err := StartJobExpectingFailure(t, ji)
		assert.Error(t, err, "error parsing docker image")
	} else {
		status, err := RunJob(t, ji)
		if err != nil {
			t.Fatal(err)
		}
		if status != TASK_FAILED {
			t.Fatalf("Expected status=FAILED, got: %s", status)
		}
	}
}

func testImageNonExistingDigestFails(t *testing.T, jobID string) {
	digest := "sha256:12345123456c6f231ea3adc7960cc7f753ebb0099999999999999a9b4dfdfdcd"
	ji := &JobInput{
		ImageName:     byDigest.name,
		ImageDigest:   digest,
		EntrypointOld: "/bin/true",
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	status, err := RunJob(t, ji)
	if err != nil {
		t.Fatal(err)
	}
	if status != TASK_FAILED {
		t.Fatalf("Expected status=FAILED, got: %s", status)
	}
}

func testImagePullError(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     alpine.name,
		Version:       "latest1",
		EntrypointOld: "/usr/bin/true",
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	status, err := RunJob(t, ji)
	if err != nil {
		t.Fatal(err)
	}
	if status != TASK_FAILED {
		t.Fatalf("Expected status=FAILED, got: %s", status)
	}
}

func testCancelPullBigImage(t *testing.T, jobID string) { // nolint: gocyclo
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobResponse, err := StartJob(t, ctx, &JobInput{
		JobID:      jobID,
		ImageName:  bigImage.name,
		Version:    bigImage.tag,
		UsePodSpec: shouldUsePodspecInTest,
	})

	require.NoError(t, err)

	select {
	case taskStatus := <-jobResponse.UpdateChan:
		if taskStatus.State.String() != "TASK_STARTING" {
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

func testBadEntrypoint(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     alpine.name,
		Version:       alpine.tag,
		EntrypointOld: "bad",
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	// We expect this to fail
	if RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testNoEntrypoint(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:  noEntrypoint.name,
		Version:    noEntrypoint.tag,
		UsePodSpec: shouldUsePodspecInTest,
	}
	// We expect this to fail
	if RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testCanWriteInLogsAndSubDirs(t *testing.T, jobID string) {
	cmd := `sh -c "mkdir -p /logs/prana && echo begining > /logs/prana/prana.log && ` +
		`mv /logs/prana/prana.log /logs/prana/prana-2016.log && echo ending >> /logs/out"`
	ji := &JobInput{
		ImageName:     alpine.name,
		Version:       alpine.tag,
		EntrypointOld: cmd,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testShutdown(t *testing.T, jobID string) {
	// This test changed from canceling the context to stop the container to calling killTask. The reason being
	// is that now we plumb through a single context from the test -> jobRunner -> runtime. This is useful for
	// things like tracing, but it makes it so that once the context is cancelled, we can no longer make calls
	// to the backend.
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()

	ji := &JobInput{
		ImageName:     alpine.name,
		Version:       alpine.tag,
		EntrypointOld: "sleep 6000",
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}

	jobRunner, err := StartJob(t, ctx, ji)
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

func testMetadataProxyInjection(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: "/bin/bash -c 'curl -sf http://169.254.169.254/latest/meta-data/local-ipv4 | grep 1.2.3.4'",
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testMetadataProxyFromLocalhost(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'curl -sf --interface 127.0.0.1 http://169.254.169.254/latest/meta-data/local-ipv4'`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testMetadataProxyOnIPv6(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'curl -sf http://[fd00:ec2::254]/latest/meta-data/local-ipv4'`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testMetadataProxyPublicIP(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: "/bin/bash -c 'curl -sf http://169.254.169.254/latest/meta-data/public-ipv4 | grep 203.0.113.11",
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testTerminateTimeoutWrapped(t *testing.T, jobID string, usePodSpec bool, killWaitSeconds uint32) (*runner.Update, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()

	// Submit a job that runs for a long time and does
	// NOT exit on SIGTERM
	ji := &JobInput{
		ImageName:       ignoreSignals.name,
		Version:         ignoreSignals.tag,
		KillWaitSeconds: killWaitSeconds,
		JobID:           jobID,
		UsePodSpec:      shouldUsePodspecInTest,
	}
	// Start the executor
	jobResponse, err := StartJob(t, ctx, ji)
	require.NoError(t, err)
	defer jobResponse.StopExecutorAsync()

	// Wait until the task is running
	for status := range jobResponse.UpdateChan {
		if status.State.IsTerminalStatus() {
			t.Fatal("Task exited prematurely (before becoming healthy)")
		}
		log.Infof("Received status update %+v", status)
		if status.State.String() == "TASK_RUNNING" && strings.Contains(status.Mesg, "health_status: healthy") {
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

func testTerminateTimeout(t *testing.T, jobID string) {
	status, killTime := testTerminateTimeoutWrapped(t, jobID, shouldUsePodspecInTest, 15)
	if status.State != titusdriver.Killed {
		t.Fail()
	}
	if killTime < time.Second*time.Duration(15) {
		t.Fatalf("Task was killed too quickly, in %s", killTime.String())
	}
}

func testTerminateTimeoutNotTooSlow(t *testing.T, jobID string) {
	status, killTime := testTerminateTimeoutWrapped(t, jobID, shouldUsePodspecInTest, 15)
	if status.State != titusdriver.Killed {
		t.Fail()
	}
	// 45 is 15 with some buffer?
	if killTime > time.Second*time.Duration(45) {
		t.Fatalf("Task wasn't killed quickly enough, in %s", killTime.String())
	}
}

func testOOMAdj(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'cat /proc/1/oom_score | grep 999'`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testOOMKill(t *testing.T, jobID string) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()

	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `stress --vm 100 --vm-keep --vm-hang 100`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}

	// Start the executor
	jobResponse, err := StartJob(t, ctx, ji)
	require.NoError(t, err)
	defer jobResponse.StopExecutorAsync()

	// Wait until the task is running
	for status := range jobResponse.UpdateChan {
		if status.State.IsTerminalStatus() {
			if status.State.String() != "TASK_FAILED" {
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

func testSchedBatch(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'schedtool 0 | grep SCHED_BATCH | grep 19'`,
		JobID:         jobID,
		SchedPolicy:   "batch",
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testSchedNormal(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'schedtool 0 | grep SCHED_NORMAL'`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testSchedIdle(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'schedtool 0 | grep SCHED_IDLE'`,
		JobID:         jobID,
		SchedPolicy:   "idle",
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testNewEnvironmentLocationPositive(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     envLabel.name,
		Version:       envLabel.tag,
		EntrypointOld: `cat /etc/nflx/base-environment.d/200titus`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testNewEnvironmentLocationNegative(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     envLabel.name,
		Version:       envLabel.tag,
		EntrypointOld: `cat /etc/profile.d/netflix_environment.sh`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingFailure(t, ji) {
		t.Fail()
	}
}

func testOldEnvironmentLocationPositive(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `cat /etc/profile.d/netflix_environment.sh`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}
func testOldEnvironmentLocationNegative(t *testing.T, jobID string) {

	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `cat /etc/nflx/base-environment.d/200titus`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingFailure(t, ji) {
		t.Fail()
	}
}

func testNoCPUBursting(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName: ubuntu.name,
		Version:   ubuntu.tag,
		// Make sure quota is set
		EntrypointOld: `/bin/bash -c 'cat /sys/fs/cgroup/cpuacct/cpu.cfs_quota_us|grep -v - -1'`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testCPUBursting(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName: ubuntu.name,
		Version:   ubuntu.tag,
		// Make sure quota is set
		EntrypointOld: `/bin/bash -c 'cat /sys/fs/cgroup/cpuacct/cpu.cfs_quota_us|grep - -1'`,
		JobID:         jobID,
		CPUBursting:   true,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testTwoCPUs(t *testing.T, jobID string) {
	var cpuCount int64 = 2
	ji := &JobInput{
		ImageName: ubuntu.name,
		Version:   ubuntu.tag,
		// Make sure quota is set
		EntrypointOld: `/bin/bash -c 'cat /sys/fs/cgroup/cpuacct/cpu.shares|grep 200'`,
		JobID:         jobID,
		CPU:           &cpuCount,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testTty(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/usr/bin/tty`,
		JobID:         jobID,
		Tty:           true,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testTtyNegative(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/usr/bin/tty`,
		JobID:         jobID,
		// Tty not specified
		UsePodSpec: shouldUsePodspecInTest,
	}
	if !RunJobExpectingFailure(t, ji) {
		t.Fail()
	}
}

func testCachedDockerPull(t *testing.T, jobID string) {
	// The no entrypoint image should never be in use by any running
	// containers, so it should be safe to delete
	dockerImageRemove(t, noEntrypoint.name+"@"+noEntrypoint.digest)
	res, err := dockerPull(t, noEntrypoint.name, noEntrypoint.digest)
	require.NoError(t, err, "No error from first docker pull")

	assert.Nil(t, res, "image shouldn't be cached")

	res, err = dockerPull(t, noEntrypoint.name, noEntrypoint.digest)
	require.NoError(t, err, "No error from second docker pull")

	assert.NotNil(t, res, "image should now be cached")
	assert.Len(t, res.RepoDigests, 1, "digest should be present")
	assert.EqualValues(t, noEntrypoint.name+"@"+noEntrypoint.digest, res.RepoDigests[0], "Correct digest should be returned")
}

func testMetatron(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:       userSet.name,
		Version:         userSet.tag,
		MetatronEnabled: true,
		// The metatron test image writes out the task identity retrieved from the metadata service to `/task-identity`
		EntrypointOld: fmt.Sprintf("/bin/bash -c \"cat /task-identity; grep %s /task-identity && grep jobAcceptedTimestampMs /task-identity | grep -E '[\\d+]'\"", jobID),
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

// Test that we return failure messages from services
func testMetatronFailure(t *testing.T, jobID string) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()

	ji := &JobInput{
		ImageName:       userSet.name,
		Version:         userSet.tag,
		MetatronEnabled: true,
		// We should never get to running this, since we're expecting the metatron service to fail before the entrypoint can run
		EntrypointOld: "grep " + jobID + " /task-identity",
		Environment: map[string]string{
			// Setting this env var causes the test metatron image to fail with the message "initialization failed"
			"TITUS_TEST_FAIL_METATRON_INIT": "true",
		},
		JobID:      jobID,
		UsePodSpec: shouldUsePodspecInTest,
	}

	jobResponse, err := StartJob(t, ctx, ji)
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
func testRunTmpFsMount(t *testing.T, jobID string) {
	var mem int64 = 256
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		Mem:           &mem,
		EntrypointOld: `/bin/bash -c 'findmnt -l -t tmpfs -o target,size | grep -e "/run[^/]" | grep 128M'`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

// Test that we can execute files in `/run`
func testExecSlashRun(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: `/bin/bash -c 'cp /bin/ls /run/ && /run/ls'`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

// Test for a container running a systemd labeled image that `/run/lock` is a tmpfs mount, and has the default size
func testSystemdImageMount(t *testing.T, jobID string) {
	var mem int64 = 256
	ji := &JobInput{
		ImageName:     systemdImage.name,
		Version:       systemdImage.tag,
		Mem:           &mem,
		EntrypointOld: `/bin/bash -c 'findmnt -l -t tmpfs -o target,size | grep -e "/run/lock[^/]" | grep 5M'`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

// Test that the size of `/dev/shm` can be set
func testShm(t *testing.T, jobID string) {
	var mem int64 = 256
	var shmSize uint32 = 192
	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		Mem:           &mem,
		ShmSize:       &shmSize,
		EntrypointOld: `/bin/bash -c 'df | grep -e '^shm' | grep 196608'`,
		JobID:         jobID,
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testContainerLogViewer(t *testing.T, jobID string) {
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
		JobID:      jobID,
		UsePodSpec: shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testnc(t *testing.T, jobID string) {
	ji := &JobInput{
		ImageName: ubuntu.name,
		Version:   ubuntu.tag,
		// Make sure that the process exits due to timeout, and not due to permission denied error
		EntrypointOld: "/usr/bin/negative-seccomp",
		UsePodSpec:    shouldUsePodspecInTest,
	}
	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}
}

func testGPUManager1GPU(t *testing.T, jobID string) {
	g := &gpuManager{}
	var gpu int64 = 1

	ji := &JobInput{
		ImageName:     ubuntu.name,
		Version:       ubuntu.tag,
		EntrypointOld: fmt.Sprintf(`/bin/bash -c 'test "${TITUS_OCI_RUNTIME}" == "%s"'`, gpuTestRuntime),
		JobID:         jobID,
		GPUManager:    g,
		GPU:           &gpu,
		UsePodSpec:    shouldUsePodspecInTest,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultFailureTimeout)
	defer cancel()

	jobResult, err := StartJob(t, ctx, ji)
	assert.Nil(t, err)

	require.True(t, jobResult.WaitForSuccess())

	if !RunJobExpectingSuccess(t, ji) {
		t.Fail()
	}

	jobResult.StopExecutor()

	assert.Equal(t, 1, g.devicesAllocated)
	assert.Equal(t, 1, g.devicesDeallocated)
}

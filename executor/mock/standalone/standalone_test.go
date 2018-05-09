package standalone

import (
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

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/executor/mock"
	"github.com/gogo/protobuf/proto"
	"github.com/mesos/mesos-go/mesosproto"
	"github.com/pborman/uuid"
	log "github.com/sirupsen/logrus"
)

var standalone bool

func init() {
	if debug, err := strconv.ParseBool(os.Getenv("DEBUG")); err == nil && debug {
		log.SetLevel(log.DebugLevel)
	}
	flag.BoolVar(&standalone, "standalone", false, "Enable standalone tests")
	flag.Parse()
}

type testImage struct {
	name string
	tag  string
}

var (
	// TODO: Determine how this got built, and add it to the auto image builders?
	alpine = testImage{
		name: "titusoss/alpine",
		tag:  "3.5",
	}
	ubuntu = testImage{
		name: "titusoss/ubuntu",
		tag:  "20180501-1525157359",
	}
	// TODO: Determine how this got built, and add it to the auto image builders?
	byDigest = testImage{
		name: "titusoss/by-digest",
		tag:  "latest",
	}
	bigImage = testImage{
		name: "titusoss/big-image",
		tag:  "20171025-1508900976",
	}
	noEntrypoint = testImage{
		name: "titusoss/no-entrypoint",
		tag:  "20180501-1525157430",
	}
	ignoreSignals = testImage{
		name: "titusoss/ignore-signals",
		tag:  "20180501-1525157636",
	}
	pty = testImage{
		name: "titusoss/pty",
		tag:  "20180507-1525733149",
	}
	xenialSystemd = testImage{
		name: "titusoss/ubuntu-systemd-xenial",
		tag:  "20180509-1525834628",
	}
)

// This file still uses log as opposed to using the testing library's built-in logging framework.
// Since we do not configure Logrus, we will just log to stderr.
func TestStandalone(t *testing.T) {
	testFunctions := []func(*testing.T, string){
		testSimpleJob,
		testSimpleJobWithBadEnvironment,
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
		testMetdataProxyDefaultRoute,
		testTerminateTimeout,
		testMakesPTY,
		testSystemdXenial,
	}
	for _, fun := range testFunctions {
		fullName := runtime.FuncForPC(reflect.ValueOf(fun).Pointer()).Name()
		splitName := strings.Split(fullName, ".")
		funName := splitName[len(splitName)-1]
		testName := strings.Title(funName)
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
		jobID := fmt.Sprintf("%s-%d-%d", funTitle, rand.Intn(1000), time.Now().Second())
		f(t, jobID)
	}
}

func testSimpleJob(t *testing.T, jobID string) {
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: "echo Hello Titus",
		JobID:      jobID,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testSimpleJobWithBadEnvironment(t *testing.T, jobID string) {
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: "echo Hello Titus",
		Environment: map[string]string{
			"ksrouter.filter.xpath.expression": `(XXXXX("XXXXXX") = "XXXXXXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXXXXXXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXX", "XXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXX", "XXXXXXXXXXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXX" XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXXX" XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX"))`,
			"BAD":     `"`,
			"AlsoBAD": "",
		},
		JobID: jobID,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testNoCapPtraceByDefault(t *testing.T, jobID string) {
	ji := &mock.JobInput{
		ImageName:  ubuntu.name,
		Version:    ubuntu.tag,
		Entrypoint: "/bin/sh -c '! (/sbin/capsh --print | tee /logs/no-ptrace.log | grep sys_ptrace')",
		JobID:      jobID,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testCanAddCapabilities(t *testing.T, jobID string) {
	ji := &mock.JobInput{
		ImageName:  ubuntu.name,
		Version:    ubuntu.tag,
		Entrypoint: "/bin/sh -c '/sbin/capsh --print | tee /logs/ptrace.log | grep sys_ptrace'",
		Capabilities: &titus.ContainerInfo_Capabilities{
			Add: []titus.ContainerInfo_Capabilities_Capability{
				titus.ContainerInfo_Capabilities_SYS_PTRACE,
			},
		},
		JobID: jobID,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

// ensure the default capability set matches what docker and rkt do:
// https://github.com/docker/docker/blob/master/oci/defaults_linux.go#L62-L77
// https://github.com/appc/spec/blob/master/spec/ace.md#linux-isolators
func testDefaultCapabilities(t *testing.T, jobID string) {
	ji := &mock.JobInput{
		ImageName: ubuntu.name,
		Version:   ubuntu.tag,
		// Older kernels (3.13 on jenkins) have a different bitmask, so we check both the new and old formats
		Entrypoint: `/bin/bash -c 'cat /proc/self/status | tee /logs/capabilities.log | egrep "CapEff:\s+(00000020a80425fb|00000000a80425fb)"'`,
		JobID:      jobID,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testMakesPTY(t *testing.T, jobID string) {
	ji := &mock.JobInput{
		ImageName:  pty.name,
		Version:    pty.tag,
		Entrypoint: "/bin/bash -c '/usr/bin/unbuffer /usr/bin/tty | grep /dev/pts'",
		JobID:      jobID,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testStdoutGoesToLogFile(t *testing.T, jobID string) {
	message := fmt.Sprintf("Some message with ID=%s, and a suffix.", uuid.New())
	cmd := fmt.Sprintf(`sh -c 'echo "%[1]s" && sleep 1 && grep "%[1]s" /logs/stdout'`, message)
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: cmd,
		JobID:      jobID,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testStderrGoesToLogFile(t *testing.T, jobID string) {
	message := fmt.Sprintf("Some message with ID=%s, and a suffix.", uuid.New())
	cmd := fmt.Sprintf(`sh -c 'echo "%[1]s" >&2 && sleep 1 && grep "%[1]s" /logs/stderr'`, message)
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: cmd,
		JobID:      jobID,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testImageByDigest(t *testing.T, jobID string) {
	digest := "sha256:2fc24d2a383c452ffe1332a60f94c618f34ece3e400c0b30c8f943bd7aeec033"
	cmd := `grep not-latest /etc/who-am-i`
	ji := &mock.JobInput{
		ImageName:   byDigest.name,
		ImageDigest: digest,
		Entrypoint:  cmd,
		JobID:       jobID,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testImageByDigestIgnoresTag(t *testing.T, jobID string) {
	digest := "sha256:2fc24d2a383c452ffe1332a60f94c618f34ece3e400c0b30c8f943bd7aeec033"
	cmd := `grep not-latest /etc/who-am-i`
	ji := &mock.JobInput{
		ImageName: byDigest.name,
		Version:   "20171024-1508896310", // should be ignored
		// This version (tag) of the image has the digest:
		// sha256:652d2dd17041cb520feae4de0a976df29af4cd1d002d19ec7c8d5204f8ab1518
		// and it doesn't have not-latest in /etc/who-am-i
		ImageDigest: digest,
		Entrypoint:  cmd,
		JobID:       jobID,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testImageInvalidDigestFails(t *testing.T, jobID string) {
	digest := "some-invalid-digest"
	ji := &mock.JobInput{
		ImageName:   byDigest.name,
		Version:     "latest", // should be ignored
		ImageDigest: digest,
		Entrypoint:  fmt.Sprintf(`/bin/true`),
		JobID:       jobID,
	}
	status, err := mock.RunJob(ji, false)
	if err != nil {
		t.Fatal(err)
	}
	if status != mesosproto.TaskState_TASK_FAILED.String() {
		t.Fatalf("Expected status=FAILED, got: %s", status)
	}
}

func testImageNonExistingDigestFails(t *testing.T, jobID string) {
	digest := "sha256:12345123456c6f231ea3adc7960cc7f753ebb0099999999999999a9b4dfdfdcd"
	ji := &mock.JobInput{
		ImageName:   byDigest.name,
		ImageDigest: digest,
		Entrypoint:  fmt.Sprintf(`/bin/true`),
		JobID:       jobID,
	}
	status, err := mock.RunJob(ji, false)
	if err != nil {
		t.Fatal(err)
	}
	if status != mesosproto.TaskState_TASK_FAILED.String() {
		t.Fatalf("Expected status=FAILED, got: %s", status)
	}
}

func testImagePullError(t *testing.T, jobID string) {
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    "latest1",
		Entrypoint: "/usr/bin/true",
		JobID:      jobID,
	}
	status, err := mock.RunJob(ji, false)
	if err != nil {
		t.Fatal(err)
	}
	if status != mesosproto.TaskState_TASK_FAILED.String() {
		t.Fatalf("Expected status=FAILED, got: %s", status)
	}
}

func testCancelPullBigImage(t *testing.T, jobID string) { // nolint: gocyclo
	jobRunner := mock.NewJobRunner()

	testResultBigImage := jobRunner.StartJob(&mock.JobInput{
		JobID:     jobID,
		ImageName: bigImage.name,
		Version:   bigImage.tag,
	})

	select {
	case taskStatus := <-testResultBigImage.UpdateChan:
		if taskStatus.State.String() != "TASK_STARTING" {
			t.Fatal("Task never observed in TASK_STARTING, instead: ", taskStatus)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Spent too long waiting for task starting")
	}

	if err := jobRunner.KillTask(); err != nil {
		t.Fatal("Could not stop task: ", err)
	}
	timeOut := time.After(30 * time.Second)
	for {
		select {
		case taskStatus := <-testResultBigImage.UpdateChan:
			//		t.Log("Observed task status: ", taskStatus)
			if taskStatus.State.String() == "TASK_RUNNING" {
				t.Fatalf("Task %s started after killTask %v", testResultBigImage.TaskID, taskStatus)
			}
			if taskStatus.State.String() == "TASK_KILLED" || taskStatus.State.String() == "TASK_LOST" {
				t.Logf("Task %s successfully terminated with status %s", testResultBigImage.TaskID, taskStatus.State.String())
				goto big_task_killed
			}
		case <-timeOut:
			t.Fatal("Cancel failed to stop job in time")
		}
	}
big_task_killed:
	// We do this here, otherwise  a stuck executor can prevent this from exiting.
	jobRunner.StopExecutor()
}

func testBadEntrypoint(t *testing.T, jobID string) {
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: "bad",
		JobID:      jobID,
	}
	// We expect this to fail
	if mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testNoEntrypoint(t *testing.T, jobID string) {
	ji := &mock.JobInput{
		ImageName: noEntrypoint.name,
		Version:   noEntrypoint.tag,
	}
	// We expect this to fail
	if mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testCanWriteInLogsAndSubDirs(t *testing.T, jobID string) {
	cmd := `sh -c "mkdir -p /logs/prana && echo begining > /logs/prana/prana.log && ` +
		`mv /logs/prana/prana.log /logs/prana/prana-2016.log && echo ending >> /logs/out"`
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: cmd,
		JobID:      jobID,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testShutdown(t *testing.T, jobID string) {
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: "sleep 6000",
		JobID:      jobID,
	}

	jobRunner := mock.NewJobRunner()
	testResult := jobRunner.StartJob(ji)
	taskRunning := make(chan bool, 10)
	go func() {
		for {
			select {
			case status := <-testResult.UpdateChan:
				if status.State.String() == "TASK_RUNNING" {
					taskRunning <- true
				} else if mock.IsTerminalState(status.State) {
					if status.State.String() != "TASK_KILLED" {
						t.Errorf("Task %s not killed successfully, %s!", testResult.TaskID, status.State.String())
					}
					taskRunning <- false
					return
				}
			case <-time.After(time.Second * 60):
				t.Errorf("Task %s did not reach RUNNING - timed out", testResult.TaskID)
				taskRunning <- false
				return
			}
		}
	}()

	<-taskRunning
	t.Logf("Task is running, stopping executor")
	jobRunner.StopExecutor()
}

func testMetadataProxyInjection(t *testing.T, jobID string) {
	ji := &mock.JobInput{
		ImageName:  ubuntu.name,
		Version:    ubuntu.tag,
		Entrypoint: "/bin/bash -c 'curl -sf http://169.254.169.254/latest/meta-data/local-ipv4 | grep 1.2.3.4'",
		JobID:      jobID,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testMetdataProxyDefaultRoute(t *testing.T, jobID string) {
	ji := &mock.JobInput{
		ImageName:  ubuntu.name,
		Version:    ubuntu.tag,
		Entrypoint: `/bin/bash -c 'curl -sf --interface $(ip route get 4.2.2.2|grep -E -o "src [0-9.]+"|cut -f2 -d" ") http://169.254.169.254/latest/meta-data/local-ipv4'`,
		JobID:      jobID,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testSystemdXenial(t *testing.T, jobID string) {
	// Start the executor
	jobRunner := mock.NewJobRunner()
	defer jobRunner.StopExecutorAsync()

	// Submit a job that runs for a long time and does
	// NOT exit on SIGTERM
	ji := &mock.JobInput{
		BaseContainerInfo: &titus.ContainerInfo{
			AllowNestedContainers: proto.Bool(true),
		},
		ImageName: xenialSystemd.name,
		Version:   xenialSystemd.tag,
		JobID:     jobID,
	}
	jobResponse := jobRunner.StartJob(ji)

	// Wait until the task is running
	for {
		status := <-jobResponse.UpdateChan
		if status.State.String() == "TASK_RUNNING" {
			break
		}
	}

	if err := jobRunner.KillTask(); err != nil {
		t.Fail()
	}

	for status := range jobResponse.UpdateChan {

		if mock.IsTerminalState(status.State) {
			t.Log("Terminated in terminal state: ", status.State)
			return
		}
	}
	t.Fail()
}

func testTerminateTimeout(t *testing.T, jobID string) {
	// Start the executor
	jobRunner := mock.NewJobRunner()
	defer jobRunner.StopExecutorAsync()

	// Submit a job that runs for a long time and does
	// NOT exit on SIGTERM
	ji := &mock.JobInput{
		ImageName:       ignoreSignals.name,
		Version:         ignoreSignals.tag,
		KillWaitSeconds: 20,
		JobID:           jobID,
	}
	jobResponse := jobRunner.StartJob(ji)

	// Wait until the task is running
	for {
		status := <-jobResponse.UpdateChan
		if status.State.String() == "TASK_RUNNING" {
			break
		}
	}

	// Submit a request to kill the job. Since the
	// job does not exit on SIGTERM we expect the kill
	// to take at least 20 seconds
	killTime := time.Now()
	if err := jobRunner.KillTask(); err != nil {
		t.Fail()
	}

	for status := range jobResponse.UpdateChan {

		if mock.IsTerminalState(status.State) {
			if status.State.String() != "TASK_KILLED" {
				t.Fail()
			}
			if time.Since(killTime) < 20*time.Second {
				t.Fatal("Task was killed too quickly")
			}
			return
		}
	}
	t.Fail()
}

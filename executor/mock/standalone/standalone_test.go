package standalone

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/executor"
	"github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/drivers/testdriver"
	"github.com/Netflix/titus-executor/executor/mock"
	"github.com/Netflix/titus-executor/models"
	"github.com/mesos/mesos-go/mesosproto"
	"github.com/pborman/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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
	alpine = testImage{
		name: "titusoss/alpine",
		tag:  "3.5",
	}
	ubuntu = testImage{
		name: "titusoss/ubuntu-test",
		tag:  "20171025-1508915634",
	}
	byDigest = testImage{
		name: "titusoss/by-digest",
		tag:  "latest",
	}
	bigImage = testImage{
		name: "titusoss/big-image",
		tag:  "20171025-1508900976",
	}
	noEntrypoint = testImage{
		name: "titusoss/no-entrypoint-test",
		tag:  "20171109-1510275133",
	}
	ignoreSignals = testImage{
		name: "titusoss/ignore-signals",
		tag:  "20180122-1516662139",
	}
)

// This file still uses log as opposed to using the testing library's built-in logging framework.
// Since we do not configure Logrus, we will just log to stderr.
func TestStandalone(t *testing.T) {
	if !standalone {
		t.Skipf("Standalone tests are not enabled! Activate with the -standalone cmdline flag.")
	}
	testFunctions := []func(*testing.T){
		testSimpleJob,
		testNoCapPtraceByDefault,
		testCanAddCapabilities,
		testDefaultCapabilities,
		testHTTPServerEndpoint,
		testLaunchAfterKill,
		testLaunchAfterKillDisableLaunchguard,
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
		testSimpleJobWithBadEnvironment,
		testTerminateTimeout,
	}
	for _, fun := range testFunctions {
		fullName := runtime.FuncForPC(reflect.ValueOf(fun).Pointer()).Name()
		splitName := strings.Split(fullName, ".")
		funName := splitName[len(splitName)-1]
		t.Run(strings.Title(funName), makeTestParallel(fun))
	}
}

func makeTestParallel(f func(*testing.T)) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		f(t)
	}
}

func testSimpleJob(t *testing.T) {
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: "echo Hello Titus",
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testSimpleJobWithBadEnvironment(t *testing.T) {
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: "echo Hello Titus",
		Environment: map[string]string{
			"ksrouter.filter.xpath.expression": `(XXXXX("XXXXXX") = "XXXXXXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXXXXXXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXX", "XXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXX", "XXXXXXXXXXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXX" XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXXX" XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX"))`,
			"BAD":     `"`,
			"AlsoBAD": "",
		},
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testNoCapPtraceByDefault(t *testing.T) {
	ji := &mock.JobInput{
		ImageName:  ubuntu.name,
		Version:    ubuntu.tag,
		Entrypoint: "/bin/sh -c '! (/sbin/capsh --print | tee /logs/no-ptrace.log | grep sys_ptrace')",
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testCanAddCapabilities(t *testing.T) {
	ji := &mock.JobInput{
		ImageName:  ubuntu.name,
		Version:    ubuntu.tag,
		Entrypoint: "/bin/sh -c '/sbin/capsh --print | tee /logs/ptrace.log | grep sys_ptrace'",
		Capabilities: &titus.ContainerInfo_Capabilities{
			Add: []titus.ContainerInfo_Capabilities_Capability{
				titus.ContainerInfo_Capabilities_SYS_PTRACE,
			},
		},
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

// ensure the default capability set matches what docker and rkt do:
// https://github.com/docker/docker/blob/master/oci/defaults_linux.go#L62-L77
// https://github.com/appc/spec/blob/master/spec/ace.md#linux-isolators
func testDefaultCapabilities(t *testing.T) {
	ji := &mock.JobInput{
		ImageName: ubuntu.name,
		Version:   ubuntu.tag,
		// Older kernels (3.13 on jenkins) have a different bitmask, so we check both the new and old formats
		Entrypoint: `/bin/bash -c 'cat /proc/self/status | tee /logs/capabilities.log | egrep "CapEff:\s+(00000020a80425fb|00000000a80425fb)"'`,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testHTTPServerEndpoint(t *testing.T) { // nolint: gocyclo
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: "sleep 5",
	}
	jobRunner := mock.NewJobRunner(true)
	jobResponse := jobRunner.StartJob(ji)
	defer jobRunner.StopExecutor()

	for status := range jobResponse.StatusChannel { // nolint: gosimple
		if status.Status != "TASK_RUNNING" {
			continue
		}
		log.Printf("HTTP Server URL obtained %v\n", jobRunner.HTTPServer.URL)
		checkURL := jobRunner.HTTPServer.URL + "/get-current-state"
		http.DefaultClient.Timeout = 5 * time.Second
		currentStateResponse, err := http.DefaultClient.Get(checkURL)
		if err != nil {
			t.Fatalf("Unable to fetch current executor state from http endpoint %s", err)
		}

		bytes, err := ioutil.ReadAll(currentStateResponse.Body)
		if err != nil {
			t.Fatalf("Unable to read current executor state from http endpoint %s", err)

		}

		var executorCurrentState models.CurrentState
		err = json.Unmarshal(bytes, &executorCurrentState)
		if err != nil {
			t.Fatalf("Unable to deserialize current executor state from http endpoint %v\n", err)
		}
		if len(executorCurrentState.Tasks) != 1 {
			t.Fatalf("Current tasks state len is %d vs expected(1)", len(executorCurrentState.Tasks))
		}

		if executorCurrentState.Tasks[jobResponse.TaskID] == "" {
			t.Fatalf("Current tasks state does not contain %s", jobResponse.TaskID)
		}
		log.Printf("Current Task state %s", executorCurrentState.Tasks[jobResponse.TaskID])
		if executorCurrentState.Tasks[jobResponse.TaskID] != titusdriver.Running.String() {
			t.Fatalf("Current tasks state incorrect for task %s - %s vs expected(%s)",
				jobResponse.TaskID,
				executorCurrentState.Tasks[jobResponse.TaskID],
				titusdriver.Running.String())
		}

		break

	}

	if !jobResponse.WaitForSuccess() {
		t.Fail()
	}
}

func testLaunchAfterKill(t *testing.T) {
	// Start the executor
	jobRunner := mock.NewJobRunner(false)
	defer jobRunner.StopExecutorAsync()

	// Submit a job that runs for a long time and does
	// NOT exit on SIGTERM
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: "sleep 600",
	}
	firstJobResponse := jobRunner.StartJob(ji)

	// Wait until the task is running
	for {
		status := <-firstJobResponse.StatusChannel
		if status.Status == "TASK_RUNNING" {
			break
		}
	}

	// Submit a request to kill the job. Since the
	// job does not exit on SIGTERM we expect the kill
	// to take at least 10 seconds.
	if err := jobRunner.KillTask(firstJobResponse.TaskID); err != nil {
		t.Fail()
	}

	// Start another task that should block while the kill is happening
	// Submit a job that runs for a long time and does
	// NOT exit on SIGTERM
	ji = &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: "sleep 6",
	}
	secondJobResponse := jobRunner.StartJob(ji)

	for {
		select {
		case firstStatus := <-firstJobResponse.StatusChannel:
			if firstStatus.Status != "TASK_KILLED" {
				t.Fatal("First status did not end up in killed state: ", firstStatus)
			}
		case secondStatus := <-secondJobResponse.StatusChannel:
			if mock.IsTerminalState(secondStatus) {
				if secondStatus.Status != "TASK_FINISHED" {
					t.Fatal("Second task ended up in terminal state: ", secondStatus)
				}
				return
			}
		}
	}
}

func testLaunchAfterKillDisableLaunchguard(t *testing.T) {
	// Start the executor
	jobRunner := mock.NewJobRunner(false)
	defer jobRunner.StopExecutorAsync()

	// Submit a job that runs for 120s and does
	// NOT exit on SIGTERM
	ji := &mock.JobInput{
		ImageName:         ignoreSignals.name,
		Version:           ignoreSignals.tag,
		IgnoreLaunchGuard: true,
		KillWaitSeconds:   30,
	}
	firstJobResponse := jobRunner.StartJob(ji)

	// Wait until the task is running
	for {
		status := <-firstJobResponse.StatusChannel
		if status.Status == "TASK_RUNNING" {
			t.Log("First task running, id: ", firstJobResponse.TaskID)
			break
		}
	}
	// The bash script inside of the container needs to run, and setup traps before we send the kill signal
	time.Sleep(5 * time.Second)

	// Submit a request to kill the job. Since the
	// job does not exit on SIGTERM we expect the kill
	// to take at least 30 seconds.
	if err := jobRunner.KillTask(firstJobResponse.TaskID); err != nil {
		t.Fail()
	}

	// Start another task that should not block while the kill is happening
	ji = &mock.JobInput{
		ImageName:         alpine.name,
		Version:           alpine.tag,
		Entrypoint:        "sleep 6",
		IgnoreLaunchGuard: true,
	}
	secondJobResponse := jobRunner.StartJob(ji)
	waitForJobs(t, firstJobResponse, secondJobResponse)
}

func waitForJobs(t *testing.T, firstJobResponse, secondJobResponse *mock.JobRunResponse) {
	var job1terminal, job2terminal bool
	var job1terminalTime, job2startTime time.Time
	statuses := []testdriver.TaskStatus{}

	for !(job1terminal && job2terminal) {
		select {
		case status := <-firstJobResponse.StatusChannel:
			statuses = append(statuses, status)
			if mock.IsTerminalState(status) {
				assert.Equal(t, "TASK_KILLED", status.Status)
				job1terminal = true
				job1terminalTime = time.Now()
			}
		case status := <-secondJobResponse.StatusChannel:
			statuses = append(statuses, status)
			if mock.IsTerminalState(status) {
				job2terminal = true
			} else if status.Status == "TASK_RUNNING" {
				job2startTime = time.Now()
			}
		}
	}
	// Test that:
	// 1. we saw no launchguard messages
	// 2. that job2 started before job1 was killed
	t.Log("Execution history ", statuses)
	assert.True(t, job2startTime.Before(job1terminalTime))
	for _, status := range statuses {
		assert.NotEqual(t, executor.WaitingOnLaunchguardMessage, status.Msg)
	}
}

func testStdoutGoesToLogFile(t *testing.T) {
	message := fmt.Sprintf("Some message with ID=%s, and a suffix.", uuid.New())
	cmd := fmt.Sprintf(`sh -c 'echo "%[1]s" && sleep 1 && grep "%[1]s" /logs/stdout'`, message)
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: cmd,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testStderrGoesToLogFile(t *testing.T) {
	message := fmt.Sprintf("Some message with ID=%s, and a suffix.", uuid.New())
	cmd := fmt.Sprintf(`sh -c 'echo "%[1]s" >&2 && sleep 1 && grep "%[1]s" /logs/stderr'`, message)
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: cmd,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testImageByDigest(t *testing.T) {
	digest := "sha256:2fc24d2a383c452ffe1332a60f94c618f34ece3e400c0b30c8f943bd7aeec033"
	cmd := `grep not-latest /etc/who-am-i`
	ji := &mock.JobInput{
		ImageName:   byDigest.name,
		ImageDigest: digest,
		Entrypoint:  cmd,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testImageByDigestIgnoresTag(t *testing.T) {
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
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testImageInvalidDigestFails(t *testing.T) {
	digest := "some-invalid-digest"
	ji := &mock.JobInput{
		ImageName:   byDigest.name,
		Version:     "latest", // should be ignored
		ImageDigest: digest,
		Entrypoint:  fmt.Sprintf(`/bin/true`),
	}
	status, err := mock.RunJob(ji, false)
	if err != nil {
		t.Fatal(err)
	}
	if status != mesosproto.TaskState_TASK_FAILED.String() {
		t.Fatalf("Expected status=FAILED, got: %s", status)
	}
}

func testImageNonExistingDigestFails(t *testing.T) {
	digest := "sha256:12345123456c6f231ea3adc7960cc7f753ebb0099999999999999a9b4dfdfdcd"
	ji := &mock.JobInput{
		ImageName:   byDigest.name,
		ImageDigest: digest,
		Entrypoint:  fmt.Sprintf(`/bin/true`),
	}
	status, err := mock.RunJob(ji, false)
	if err != nil {
		t.Fatal(err)
	}
	if status != mesosproto.TaskState_TASK_FAILED.String() {
		t.Fatalf("Expected status=FAILED, got: %s", status)
	}
}

func testImagePullError(t *testing.T) {
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    "latest1",
		Entrypoint: "/usr/bin/true",
	}
	status, err := mock.RunJob(ji, false)
	if err != nil {
		t.Fatal(err)
	}
	if status != mesosproto.TaskState_TASK_FAILED.String() {
		t.Fatalf("Expected status=FAILED, got: %s", status)
	}
}

func testCancelPullBigImage(t *testing.T) { // nolint: gocyclo
	jobRunner := mock.NewJobRunner(false)

	bigImageJobID := fmt.Sprintf("Skynet-%v%v", rand.Intn(1000), time.Now().Second())
	testResultBigImage := jobRunner.StartJob(&mock.JobInput{
		JobID:     bigImageJobID,
		ImageName: bigImage.name,
		Version:   bigImage.tag,
	})

	select {
	case taskStatus := <-testResultBigImage.StatusChannel:
		if taskStatus.Status != "TASK_STARTING" {
			t.Fatal("Task never observed in TASK_STARTING, instead: ", taskStatus)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Spent too long waiting for task starting")
	}

	if err := jobRunner.KillTask(testResultBigImage.TaskID); err != nil {
		t.Fatal("Could not stop task: ", err)
	}
	smallImageJobID := fmt.Sprintf("alpine-%v%v", rand.Intn(1000), time.Now().Second())
	c := make(chan *mock.JobRunResponse, 1)
	go func() {
		defer close(c)
		c <- jobRunner.StartJob(&mock.JobInput{
			JobID:      smallImageJobID,
			ImageName:  alpine.name,
			Version:    alpine.tag,
			Entrypoint: "/bin/sleep 5",
		})
		t.Log("Starting small container")
	}()

	timeOut := time.After(30 * time.Second)
	for {
		select {
		case taskStatus := <-testResultBigImage.StatusChannel:
			t.Log("Observed task status: ", taskStatus)
			if taskStatus.Status == "TASK_RUNNING" {
				t.Fatalf("Task %s started after killTask %v", testResultBigImage.TaskID, taskStatus)
			}
			if taskStatus.Status == "TASK_KILLED" || taskStatus.Status == "TASK_LOST" {
				t.Logf("Task %s successfully terminated with status %s", testResultBigImage.TaskID, taskStatus.Status)
				goto big_task_killed
			}
		case <-timeOut:
			t.Fatal("Cancel failed to stop job in time")
		}
	}
big_task_killed:
	t.Log("Big Image successfully stopped, trying to start follow-on job")

	var testResultSmallImage *mock.JobRunResponse
	select {
	case testResultSmallImage = <-c:
	case <-time.After(30 * time.Second):
		t.Fatal("Unable to get small image result after 30 seconds")
	}

	for {
		select {
		case taskStatus := <-testResultSmallImage.StatusChannel:
			if taskStatus.Status == "TASK_FINISHED" {
				t.Log("Small job finished")
				goto small_task_finished
			}
		case <-time.After(60 * time.Second):
			t.Fatal("Launchguard probably stuck, small job did not start in 60 seconds")
		}
	}
small_task_finished:

	t.Log("Test completed, shutting down")
	// We do this here, otherwise  a stuck executor can prevent this from exiting.
	jobRunner.StopExecutor()
}

func testBadEntrypoint(t *testing.T) {
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: "bad",
	}
	// We expect this to fail
	if mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testNoEntrypoint(t *testing.T) {
	ji := &mock.JobInput{
		ImageName: noEntrypoint.name,
		Version:   noEntrypoint.tag,
	}
	// We expect this to fail
	if mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testCanWriteInLogsAndSubDirs(t *testing.T) {
	cmd := `sh -c "mkdir -p /logs/prana && echo begining > /logs/prana/prana.log && ` +
		`mv /logs/prana/prana.log /logs/prana/prana-2016.log && echo ending >> /logs/out"`
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: cmd,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testShutdown(t *testing.T) {
	ji := &mock.JobInput{
		ImageName:  alpine.name,
		Version:    alpine.tag,
		Entrypoint: "sleep 6000",
	}

	jobRunner := mock.NewJobRunner(false)
	testResult := jobRunner.StartJob(ji)
	taskRunning := make(chan bool, 10)
	go func() {
		for {
			select {
			case status := <-testResult.StatusChannel:
				if status.Status == "TASK_RUNNING" {
					taskRunning <- true
				} else if mock.IsTerminalState(status) {
					if status.Status != "TASK_KILLED" {
						t.Errorf("Task %s not killed successfully, %s!", testResult.TaskID, status.Status)
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
	numTasks := jobRunner.GetNumTasks()
	if numTasks != 0 {
		t.Fatalf("Failed to shutdown all tasks, %d still running", numTasks)
	}
}

func testMetadataProxyInjection(t *testing.T) {
	ji := &mock.JobInput{
		ImageName:  ubuntu.name,
		Version:    ubuntu.tag,
		Entrypoint: "/bin/bash -c 'curl -sf http://169.254.169.254/latest/meta-data/local-ipv4 | grep 1.2.3.4'",
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testMetdataProxyDefaultRoute(t *testing.T) {
	ji := &mock.JobInput{
		ImageName:  ubuntu.name,
		Version:    ubuntu.tag,
		Entrypoint: `/bin/bash -c 'curl -sf --interface $(ip route get 4.2.2.2|grep -E -o "src [0-9.]+"|cut -f2 -d" ") http://169.254.169.254/latest/meta-data/local-ipv4'`,
	}
	if !mock.RunJobExpectingSuccess(ji, false) {
		t.Fail()
	}
}

func testTerminateTimeout(t *testing.T) {
	// Start the executor
	jobRunner := mock.NewJobRunner(false)
	defer jobRunner.StopExecutorAsync()

	// Submit a job that runs for a long time and does
	// NOT exit on SIGTERM
	ji := &mock.JobInput{
		ImageName:       ignoreSignals.name,
		Version:         ignoreSignals.tag,
		KillWaitSeconds: 20,
	}
	jobResponse := jobRunner.StartJob(ji)

	// Wait until the task is running
	for {
		status := <-jobResponse.StatusChannel
		if status.Status == "TASK_RUNNING" {
			break
		}
	}

	// Submit a request to kill the job. Since the
	// job does not exit on SIGTERM we expect the kill
	// to take at least 20 seconds
	killTime := time.Now()
	if err := jobRunner.KillTask(jobResponse.TaskID); err != nil {
		t.Fail()
	}

	for status := range jobResponse.StatusChannel {

		if mock.IsTerminalState(status) {
			if status.Status != "TASK_KILLED" {
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

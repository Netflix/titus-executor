package reaper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/models"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	log "github.com/sirupsen/logrus"

	"io"

	docker "github.com/docker/docker/client"
)

// Reaper is a holder struct for the internal configuration of the reaper
type Reaper struct {
	reporter metrics.Reporter
	log      log.Entry
}

func newReaper(ctx context.Context) *Reaper {
	l := log.NewEntry(log.New())

	return &Reaper{
		reporter: metrics.New(ctx, l, nil),
		log:      *l,
	}

}

// RunReaper runs the reap loop
func RunReaper(dockerHost string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reaper := newReaper(ctx)
	reaper.watchLoop(ctx, dockerHost)
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: time.Second * 5,
	}
}

// Watches state from Docker
func (reaper *Reaper) watchLoop(parentCtx context.Context, dockerHost string) {
	/*
		If we get disconnected from Dockerd, it probably means Dockerd has crashed (or the computer has paused / gone to sleep).
		It is not our job to fix this, and given we restart quickly, it shouldn't be a problem.

		Serving no data is better than serving bad (stale) data.
	*/
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	httpClient := newHTTPClient()
	dockerClient, err := docker.NewClient(dockerHost, "", nil, nil)
	if err != nil {
		log.Fatal("Unable to connect to Docker: ", err)
	}
	ticker := time.After(1 * time.Second)

	for {
		select {
		case <-ticker:
			reaper.log.Info("Beginning cycle")
			reaper.runReapCycle(ctx, httpClient, dockerClient)

			ticker = time.After(time.Minute)
		case <-ctx.Done():
			return
		}
	}
}

func (reaper *Reaper) runReapCycle(parentCtx context.Context, httpClient *http.Client, dockerClient *docker.Client) {
	ctx, cancel := context.WithTimeout(parentCtx, 60*time.Second)
	defer cancel()
	filter := filters.NewArgs()
	filter.Add("status", "running")
	filter.Add("status", "paused")
	filter.Add("status", "exited")
	filter.Add("status", "dead")
	filter.Add("status", "created")

	containers, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{Filters: filter, All: true})
	if err != nil {
		reaper.log.Fatal("Unable to get containers: ", err)
	}

	titusContainers := filterTitusContainers(containers)
	/* Now we have to inspect these to get the container JSON */
	for _, container := range titusContainers {
		reaper.processContainer(ctx, container, httpClient, dockerClient)
	}
}

func filterTitusContainers(containers []types.Container) []types.Container {
	ret := []types.Container{}
	for _, container := range containers {
		if _, ok := container.Labels[models.ExecutorPidLabel]; ok {
			if time.Since(time.Unix(container.Created, 0)) > 5*time.Minute {
				ret = append(ret, container)
			}
		}
	}
	return ret
}

func (reaper *Reaper) processContainer(ctx context.Context, container types.Container, httpClient *http.Client, dockerClient *docker.Client) {
	containerJSON, err := dockerClient.ContainerInspect(ctx, container.ID)
	taskID := containerJSON.Config.Labels[models.TaskIDLabel]
	l := reaper.log.WithField("taskID", taskID)
	if docker.IsErrContainerNotFound(err) {
		return
	} else if err != nil {
		reaper.log.Fatal("Unable to fetch container JSON: ", err)
	}

	if shouldTerminate(ctx, &reaper.log, containerJSON, httpClient) {
		l.Info("Terminating container")
		timeout := 30 * time.Second
		if err := dockerClient.ContainerStop(ctx, containerJSON.ID, &timeout); err != nil {
			l.Warning("Unable to stop container: ", err)
		}
		if err := dockerClient.ContainerRemove(ctx, containerJSON.ID, types.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil {
			l.Warning("Unable to remove container: ", err)
		}
		reaper.reporter.Counter("titusAgent.containersTerminatedSuccess", 1, nil)
	}
}

func shouldTerminate(ctx context.Context, logger *log.Entry, container types.ContainerJSON, httpClient *http.Client) bool {
	executorPid := container.Config.Labels[models.ExecutorPidLabel]
	executorHTTPListenerAddress := container.Config.Labels[models.ExecutorHTTPListenerAddressLabel]
	taskID := container.Config.Labels[models.TaskIDLabel]
	l := logger.WithField("taskID", taskID)
	/*
		Steps:
		1. Check if the executor PID exists
		2. Check if we can hit the Executor bind URI, and find out about the container
		3. Check if the container status is "right"
	*/
	if !isPidAlive(executorPid) {
		return true
	}

	if !executorThinksIsAlive(ctx, l, httpClient, executorHTTPListenerAddress, taskID) {
		return true
	}

	return false
}

func executorThinksIsAlive(ctx context.Context, l *log.Entry, httpClient *http.Client, executorHTTPListenerAddress, taskID string) bool {
	var containerStates models.CurrentState

	URI := fmt.Sprintf("http://%s/get-current-state", executorHTTPListenerAddress)
	req, err := http.NewRequest("GET", URI, nil)
	if err != nil {
		log.Fatal("Unable to build HTTP request: ", err)
	}

	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		log.Warningf("Unable to connect to executor %s because: %+v, assuming task death", executorHTTPListenerAddress, err)
		return false
	}
	defer shouldClose(resp.Body)

	err = json.NewDecoder(resp.Body).Decode(&containerStates)
	if err != nil {
		log.Warningf("Unable to decode response from executor %s because +%v", executorHTTPListenerAddress, err)
		return false
	}

	if taskState, ok := containerStates.Tasks[taskID]; !ok {
		l.Info("Task ID not in executor Task map")
		return false
	} else if taskState == "" || taskState == "TASK_FINISHED" || taskState == "TASK_FAILED" || taskState == "TASK_KILLED" || taskState == "TASK_LOST" {
		l.WithField("executorAddress", executorHTTPListenerAddress).WithField("taskState", taskState).Infof("Found task ID in state %s, but Docker container was not removed", taskState)
		return false
	}

	return true
}

func shouldClose(c io.Closer) {
	if err := c.Close(); err != nil {
		log.Warning("Errror closing body: ", err)
	}
}

func isPidAlive(pidStr string) bool {
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		panic(err)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		/*
			On Unix systems, FindProcess always succeeds and returns a Process for the given pid, regardless of whether the process exists.
			https://golang.org/pkg/os/#FindProcess
		*/
		log.Error("OS.FindProcess should never return an error, but: ", err)
		return false
	}

	ret := process.Signal(syscall.Signal(0))

	if ret == nil {
		return true
	} else if os.IsPermission(ret) {
		return true
	} else if os.IsNotExist(ret) {
		return false
	}
	log.Debug("Unknown error in response to kill 0: ", ret)
	return false

}

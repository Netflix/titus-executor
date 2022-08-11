package reaper

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/models"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	docker "github.com/docker/docker/client"
	"github.com/hashicorp/go-multierror"
	"github.com/sirupsen/logrus"
)

var (
	timeout = 30 * time.Second
)

// RunReaper runs reaper as a one-shot
func RunReaper(ctx context.Context, dockerHost string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	client, err := docker.NewClientWithOpts(docker.WithHost(dockerHost))
	if err != nil {
		return fmt.Errorf("Cannot initialize docker client")
	}

	return reap(ctx, client)
}

func reap(ctx context.Context, dockerClient *docker.Client) error {
	filter := filters.NewArgs()
	filter.Add("status", "running")
	filter.Add("status", "paused")
	filter.Add("status", "exited")
	filter.Add("status", "dead")
	filter.Add("status", "created")

	containers, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{Filters: filter, All: true})
	if err != nil {
		return fmt.Errorf("Unable to get containers: %w", err)
	}

	titusContainers := filterTitusContainers(containers)
	/* Now we have to inspect these to get the container JSON */
	var result *multierror.Error
	for _, container := range titusContainers {
		err = processContainer(ctx, container, dockerClient)
		if err != nil {
			result = multierror.Append(result, err)
		}
	}

	return result.ErrorOrNil()
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

func processContainer(ctx context.Context, container types.Container, dockerClient *docker.Client) error {
	logrus.WithField("container", container).Debug("Checking container")
	containerJSON, err := dockerClient.ContainerInspect(ctx, container.ID)
	if docker.IsErrNotFound(err) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("Unable to fetch container JSON: %w", err)
	}

	return processContainerJSON(ctx, containerJSON, dockerClient)
}

type client interface {
	ContainerStop(ctx context.Context, containerID string, timeout *time.Duration) error
	ContainerRemove(ctx context.Context, container string, options types.ContainerRemoveOptions) error
}

func processContainerJSON(ctx context.Context, container types.ContainerJSON, dockerClient client) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	taskID, ok := container.Config.Labels[models.TaskIDLabel]
	if !ok {
		return fmt.Errorf("Did not find task ID label on container %q", container.ID)
	}
	l := logrus.WithField("taskID", taskID)

	// We filter for this label in filterContainers above
	executorPid := container.Config.Labels[models.ExecutorPidLabel]

	exe := filepath.Join("/proc", executorPid, "exe")
	stat, err := os.Stat(exe)
	if os.IsNotExist(err) {
		var result *multierror.Error
		l.Info("Terminating container")
		if err := dockerClient.ContainerStop(ctx, container.ID, &timeout); err != nil {
			l.WithError(err).Warning("Unable to stop container")
			result = multierror.Append(result, fmt.Errorf("Unable to stop container %q: %w", container.ID, err))
		}
		if err := dockerClient.ContainerRemove(ctx, container.ID, types.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil {
			l.WithError(err).Warning("Unable to remove container")
			result = multierror.Append(result, fmt.Errorf("Unable to remove container %q: %w", container.ID, err))
		}
		err = result.ErrorOrNil()
		if err != nil {
			l.WithError(err).Error("Unable to terminate container")
		}
		return err
	}

	if err != nil {
		l.WithError(err).Error("Unable to determine if container is running or not")
		return fmt.Errorf("Unable to determine if container is running or not: %w", err)
	}

	link, err := os.Readlink(exe)
	if err != nil {
		l.WithError(err).Error("Could not readlink exe path")
		return fmt.Errorf("Could not readlink exe path: %w", err)
	}

	if !strings.HasPrefix(link, "/apps/titus-executor") {
		l.WithField("exe", exe).Warning("Could not determine is process is titus executor")
		return fmt.Errorf("Could not determine whether or not process with exe %q / and stat %v was a titus executor", link, stat)
	}

	checkIfFuseWedgedPidNs(container.State.Pid, taskID)

	l.WithFields(map[string]interface{}{
		"link": link,
		"exe":  exe,
		"stat": stat,
	}).Debug("Processed container and found consistent state")

	return nil
}

package backend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	titusdriver "github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	errContainerInfo = errors.New("Cannot find container info")
)

func state2phase(state titusdriver.TitusTaskState) v1.PodPhase {
	switch state {
	case titusdriver.Starting:
		return v1.PodPending
	case titusdriver.Running:
		return v1.PodRunning
	case titusdriver.Finished:
		return v1.PodSucceeded
	case titusdriver.Failed:
		return v1.PodFailed
	case titusdriver.Killed:
		return v1.PodFailed
	case titusdriver.Lost:
		return v1.PodFailed
	default:
		panic(state)
	}
}

func getTerminatedContainerState(prevState *v1.ContainerState) v1.ContainerState {
	terminated := v1.ContainerState{
		Terminated: &v1.ContainerStateTerminated{
			FinishedAt: metav1.NewTime(time.Now()),
			ExitCode:   -1,
		},
	}

	if prevState != nil && prevState.Running != nil {
		terminated.Terminated.StartedAt = prevState.Running.StartedAt
	}

	return terminated
}

func state2containerState(prevState *v1.ContainerState, currState titusdriver.TitusTaskState) v1.ContainerState {
	switch currState {
	case titusdriver.Starting:
		return v1.ContainerState{
			Waiting: &v1.ContainerStateWaiting{},
		}
	case titusdriver.Running:
		return v1.ContainerState{
			Running: &v1.ContainerStateRunning{
				StartedAt: metav1.NewTime(time.Now()),
			},
		}
	case titusdriver.Finished:
		return getTerminatedContainerState(prevState)
	case titusdriver.Failed:
		return getTerminatedContainerState(prevState)
	case titusdriver.Killed:
		return getTerminatedContainerState(prevState)
	case titusdriver.Lost:
		return getTerminatedContainerState(prevState)
	default:
		panic(currState)
	}
}

func RunWithBackend(ctx context.Context, runner *runner.Runner, statuses *os.File, pod *v1.Pod) error {
	containerInfoStr, ok := pod.GetAnnotations()["containerInfo"]
	if !ok {
		return errContainerInfo
	}
	data, err := base64.StdEncoding.DecodeString(containerInfoStr)
	if err != nil {
		return errors.Wrap(err, "Could not decode containerInfo from base64")
	}
	var containerInfo titus.ContainerInfo

	err = proto.Unmarshal(data, &containerInfo)
	if err != nil {
		return errors.Wrap(err, "Could not deserialize protobuf")
	}

	limits := pod.Spec.Containers[0].Resources.Limits

	// TODO: pick one, agreed upon resource name after migration to k8s scheduler is complete.
	disk, _ := resource.ParseQuantity("2G")
	for _, k := range []v1.ResourceName{v1.ResourceEphemeralStorage, v1.ResourceStorage, "titus/disk"} {
		if v, ok := limits[k]; ok {
			disk = v
			break
		}
	}

	// TODO: pick one, agreed upon resource name after migration to k8s scheduler is complete.
	gpu, _ := resource.ParseQuantity("0")
	for _, k := range []v1.ResourceName{"nvidia.com/gpu", "titus/gpu"} {
		if v, ok := limits[k]; ok {
			gpu = v
			break
		}
	}

	cpu := limits[v1.ResourceCPU]
	memory := limits[v1.ResourceMemory]
	network := limits["titus/network"]

	err = runner.StartTask(
		pod.GetName(),
		&containerInfo,
		memory.Value(),
		cpu.Value(),
		gpu.Value(),
		uint64(disk.Value()),
		uint64(network.Value()))
	if err != nil {
		return errors.Wrap(err, "Could not start task")
	}

	encoder := json.NewEncoder(statuses)
	var lock sync.Mutex

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, unix.SIGUSR1, unix.SIGTERM)
		select {
		case sig := <-ch:
			switch sig {
			case unix.SIGUSR1:
				log.G(ctx).WithField("signal", sig).Info("Terminating pod due to signal")
				runner.Kill()
			case unix.SIGTERM:
				log.G(ctx).WithField("signal", sig).Info("Terminating pod due to signal")
				runner.Kill()
			case os.Interrupt:
				log.G(ctx).WithField("signal", sig).Info("Terminating pod due to signal")
				runner.Kill()
			}
		case <-ctx.Done():
			return
		}
	}()

	for {
		select {
		case update, ok := <-runner.UpdatesChan:
			if !ok {
				return nil
			}

			lock.Lock()
			pod.Status.Message = update.Mesg
			if update.Details != nil {
				pod.Status.PodIP = update.Details.NetworkConfiguration.IPAddress
			}

			pod.Status.Reason = update.State.String()
			pod.Status.Phase = state2phase(update.State)

			var prevContainerState *v1.ContainerState
			if pod.Status.ContainerStatuses != nil && len(pod.Status.ContainerStatuses) > 0 {
				prevContainerState = &pod.Status.ContainerStatuses[0].State
			}

			log.G(ctx).WithField("pod", fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)).Debug("Setting ContainerStatus...")
			pod.Status.ContainerStatuses = []v1.ContainerStatus{{
				Name:                 pod.Name,
				State:                state2containerState(prevContainerState, update.State),
				LastTerminationState: v1.ContainerState{},
				Ready:                true,
				RestartCount:         0,
				Image:                "",
				ImageID:              "",
				ContainerID:          "",
			}}

			if update.Details != nil && update.Details.NetworkConfiguration != nil {
				for k, v := range update.Details.NetworkConfiguration.ToMap() {
					pod.Annotations[k] = v
				}
			}

			log.G(ctx).WithField("pod", fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)).Debugf("Updating pod in backend: %+v", pod)
			err = encoder.Encode(pod)
			lock.Unlock()

			if err != nil {
				log.G(ctx).WithError(err).Fatal()
			}
		case <-runner.StoppedChan:
			return nil
		case <-ctx.Done():
			// We should probably kill the pod gracefully now.
			runner.Kill()
			log.G(ctx).Info("Context complete, terminating gracefully")
			<-runner.StoppedChan
			log.G(ctx).Info("Context completed, terminated")
			return nil
		}
	}
}

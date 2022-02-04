package backend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	titusdriver "github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/runner"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/logger"
	podCommon "github.com/Netflix/titus-kube-common/pod"
	resourceCommon "github.com/Netflix/titus-kube-common/resource"
	units "github.com/docker/go-units"
	"github.com/golang/protobuf/proto" // nolint: staticcheck
	"github.com/google/renameio"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

var (
	errContainerInfo = errors.New("cannot find container info annotation")
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

func resourceBytesToMiB(r *resource.Quantity) (resource.Quantity, error) {
	rInt, ok := r.AsInt64()
	if !ok {
		zeroQuant := resource.NewQuantity(0, resource.BinarySI)
		return *zeroQuant, errors.New("dimension parsing error")
	}

	res := resource.NewQuantity(rInt/units.MiB, resource.BinarySI)
	return *res, nil
}

func resourceBytesToMB(r *resource.Quantity) (resource.Quantity, error) {
	rInt, ok := r.AsInt64()
	if !ok {
		zeroQuant := resource.NewQuantity(0, resource.DecimalSI)
		return *zeroQuant, errors.New("dimension parsing error")
	}

	res := resource.NewQuantity(rInt/units.MB, resource.DecimalSI)
	return *res, nil
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

type Backend struct {
	network, disk, memory, gpu, cpu resource.Quantity
	pod                             *v1.Pod
	containerinfo                   *titus.ContainerInfo
	readyErr                        error
	readyLock                       sync.RWMutex
	m                               metrics.Reporter
	rp                              runtimeTypes.ContainerRuntimeProvider
	cfg                             *config.Config
}

func getContainerInfo(pod *v1.Pod) (string, error) {
	containerInfoStr, ok := pod.GetAnnotations()["containerInfo"]
	if ok {
		return containerInfoStr, nil
	}

	containerInfoStr, ok = pod.GetAnnotations()[podCommon.AnnotationKeyPodTitusContainerInfo]
	if !ok {
		return "", errContainerInfo
	}

	return containerInfoStr, nil
}

func NewBackend(ctx context.Context, rp runtimeTypes.ContainerRuntimeProvider, pod *v1.Pod, cfg *config.Config, m metrics.Reporter) (*Backend, error) {
	var containerInfo titus.ContainerInfo

	podSchemaVer, err := podCommon.PodSchemaVersion(pod)
	if err != nil {
		return nil, err
	}

	// As of pod schema v1, the containerInfo annotation is optional.
	if podSchemaVer < 1 {
		containerInfoStr, err := getContainerInfo(pod)
		if err != nil {
			return nil, err
		}

		data, err := base64.StdEncoding.DecodeString(containerInfoStr)
		if err != nil {
			return nil, errors.Wrap(err, "Could not decode containerInfo from base64")
		}

		err = proto.Unmarshal(data, &containerInfo)
		if err != nil {
			return nil, errors.Wrap(err, "Could not deserialize protobuf")
		}
	}

	// All limits for the entire pod are encoded by the limits of the first container.
	// We don't currently support per-container limits.
	limits := pod.Spec.Containers[0].Resources.Limits
	disk := limits[resourceCommon.ResourceNameDisk]
	gpu := limits[resourceCommon.ResourceNameNvidiaGpu]
	cpu := limits[v1.ResourceCPU]
	memory := limits[v1.ResourceMemory]
	network := limits[resourceCommon.ResourceNameNetwork]

	// The control plane has passed resource values in bytes, but the runner takes
	// MiB / MB, so we need to do the conversion.
	disk, err = resourceBytesToMiB(&disk)
	if err != nil {
		return nil, errors.New("error converting disk resource units")
	}

	memory, err = resourceBytesToMiB(&memory)
	if err != nil {
		return nil, errors.New("error converting memory resource units")
	}

	network, err = resourceBytesToMB(&network)
	if err != nil {
		return nil, errors.New("error converting network resource units")
	}

	be := &Backend{
		network:       network,
		disk:          disk,
		memory:        memory,
		gpu:           gpu,
		cpu:           cpu,
		pod:           pod,
		containerinfo: &containerInfo,
		m:             m,
		rp:            rp,
		cfg:           cfg,
	}
	be.readyLock.Lock()

	return be, nil
}

func (b *Backend) Ready(ctx context.Context) error {
	b.readyLock.RLock()
	defer b.readyLock.RUnlock()
	return b.readyErr
}

func (b *Backend) run(ctx context.Context) (*runner.Runner, error) {
	r, err := runner.StartTaskWithRuntime(ctx, runner.Task{
		TaskID:    b.pod.GetName(),
		TitusInfo: b.containerinfo,
		Pod:       b.pod,
		Mem:       b.memory.Value(),
		CPU:       b.cpu.Value(),
		Gpu:       b.gpu.Value(),
		Disk:      b.disk.Value(),
		Network:   b.network.Value(),
	}, b.m, b.rp, *b.cfg)
	b.readyErr = err

	if err != nil {
		return nil, errors.Wrap(err, "Could not start task")
	}
	go b.waitForTerminationSignal(ctx, r)
	return r, nil
}

func (b *Backend) waitForTerminationSignal(ctx context.Context, r *runner.Runner) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, unix.SIGUSR1, unix.SIGTERM)
	// TODO: Should we always call r.Kill(), here?
	select {
	case sig := <-ch:
		logger.G(ctx).WithField("signal", sig).Info("Terminating pod due to signal")
		r.Kill()
	case <-ctx.Done():
		return
	}
}

func (b *Backend) writePod(ctx context.Context, statedir string) error {
	f, err := renameio.TempFile(statedir, filepath.Join(statedir, "state.json"))
	if err != nil {
		return fmt.Errorf("Cannot create temporary pod file")
	}

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "\t")
	err = encoder.Encode(b.pod)
	if err != nil {
		_ = f.Cleanup()
		return fmt.Errorf("Unable to marshal pod object: %w", err)
	}

	return f.CloseAtomicallyReplace()
}

func (b *Backend) RunWithOutputDir(ctx context.Context, dir string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	r, err := b.run(ctx)
	if err != nil {
		b.readyLock.Unlock()
		b.handleUpdate(ctx, runner.Update{
			TaskID: b.pod.Name,
			State:  titusdriver.Lost,
			Mesg:   fmt.Sprintf("error launching task: %s", err.Error()),
		})
		err = b.writePod(ctx, dir)
		if err != nil {
			logger.G(ctx).WithError(err).Fatal("Unable to update pod directory")
		} else {
			logger.G(ctx).Info("Updated pod dir")
		}

		return err
	}
	err = b.writePod(ctx, dir)
	b.readyLock.Unlock()
	if err != nil {
		return err
	}

	for {
		select {
		case update, ok := <-r.UpdatesChan:
			if !ok {
				return nil
			}
			b.handleUpdate(ctx, update)
			err = b.writePod(ctx, dir)
			if err != nil {
				logger.G(ctx).WithError(err).Fatal("Unable to update pod directory")
				return err
			}
			logger.G(ctx).Info("Updated pod dir")
		case <-r.StoppedChan:
			return nil
		case <-ctx.Done():
			// We should probably kill the pod gracefully now.
			r.Kill()
			logger.G(ctx).Info("Context complete, terminating gracefully")
			<-r.StoppedChan
			logger.G(ctx).Info("Context completed, terminated")
			return nil
		}
	}
}

func (b *Backend) handleUpdate(ctx context.Context, update runner.Update) {
	b.pod.Status.Message = update.Mesg
	if update.Details != nil {
		b.pod.Status.PodIP = update.Details.NetworkConfiguration.IPAddress

		// We only get to have 1 IPv4 and 1 IPv6 address in this array
		// https://github.com/kubernetes/kubernetes/blob/31030820be979ea0b2c39e08eb18fddd71f353ed/pkg/apis/core/validation/validation.go#L3289
		// So the best we can do is, if we have an EIP, we put it here, and leave the main `PodIP`
		// as the non-EIP one.
		if update.Details.NetworkConfiguration.ElasticIPAddress != "" {
			b.pod.Status.PodIPs = []v1.PodIP{
				{IP: update.Details.NetworkConfiguration.ElasticIPAddress},
			}
		} else if update.Details.NetworkConfiguration.IPAddress != "" {
			b.pod.Status.PodIPs = []v1.PodIP{
				{IP: update.Details.NetworkConfiguration.IPAddress},
			}
		}

		// And now, V6, if we have one
		// TODO: append a non-eip v6 if we can determine that we have one
		if update.Details.NetworkConfiguration.EniIPv6Address != "" {
			b.pod.Status.PodIPs = append(b.pod.Status.PodIPs, v1.PodIP{
				IP: update.Details.NetworkConfiguration.EniIPv6Address,
			})
		}
	}

	b.pod.Status.Reason = update.State.String()
	b.pod.Status.Phase = state2phase(update.State)

	var prevContainerState *v1.ContainerState
	if b.pod.Status.ContainerStatuses != nil && len(b.pod.Status.ContainerStatuses) > 0 {
		prevContainerState = &b.pod.Status.ContainerStatuses[0].State
	}

	logger.G(ctx).WithField("pod", fmt.Sprintf("%s/%s", b.pod.Namespace, b.pod.Name)).Debug("Setting ContainerStatus...")
	// Order is important here, we need the first (0th) container to be the main one so that
	// other code that looks at the first container status continues to behave in a compatible way
	mainContainerStatus := v1.ContainerStatus{
		Name:                 b.pod.Name,
		State:                state2containerState(prevContainerState, update.State),
		LastTerminationState: v1.ContainerState{},
		Ready:                true,
		RestartCount:         0,
		Image:                b.pod.Spec.Containers[0].Image,
		ImageID:              "",
		ContainerID:          "",
	}

	b.pod.Status.ContainerStatuses = []v1.ContainerStatus{mainContainerStatus}

	if update.Details != nil && update.Details.NetworkConfiguration != nil {
		for k, v := range update.Details.NetworkConfiguration.ToMap() {
			b.pod.Annotations[k] = v
		}
	}
}

func (b *Backend) RunWithStatusFile(ctx context.Context, statuses *os.File) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	runner, err := b.run(ctx)
	b.readyLock.Unlock()
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(statuses)
	var lock sync.Mutex
	for {
		select {
		case update, ok := <-runner.UpdatesChan:
			if !ok {
				return nil
			}

			lock.Lock()
			b.handleUpdate(ctx, update)
			logger.G(ctx).WithField("pod", fmt.Sprintf("%s/%s", b.pod.Namespace, b.pod.Name)).Debugf("Updating pod in backend: %+v", b.pod)
			err = encoder.Encode(b.pod)
			lock.Unlock()

			if err != nil {
				logger.G(ctx).WithError(err).Fatal()
			}
		case <-runner.StoppedChan:
			return nil
		case <-ctx.Done():
			// We should probably kill the pod gracefully now.
			runner.Kill()
			logger.G(ctx).Info("Context complete, terminating gracefully")
			<-runner.StoppedChan
			logger.G(ctx).Info("Context completed, terminated")
			return nil
		}
	}
}

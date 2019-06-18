package provider

import (
	"context"
	"encoding/json"
	"github.com/Netflix/titus-executor/vk/backend"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"k8s.io/api/core/v1"
	"os"
	"os/exec"
	"sync"
	"time"
)

type runtimePod struct {
	lock     sync.Mutex
	pod      *v1.Pod
	cmd      *exec.Cmd
	killTimer *time.Timer
	provider *AgentProvider
}

// This should be configurable, I'm just being lazy
const DefaultBackendPath = "./virtual-kubelet-backend"

func (rp *runtimePod) run(ctx context.Context) error {
	path, err := exec.LookPath(DefaultBackendPath)
	if err != nil {
		return err
	}

	f, err := writePod(rp.pod)
	log.G(ctx).WithField("filename", f.Name()).Info("Wrote podspec")

	pipe, err := backend.CreateStatusPipe(rp.pod)
	if err != nil {
		log.G(ctx).WithError(err).WithField("pipe", pipe).Info("Failed to create pipe")
		return err
	} else {
		log.G(ctx).WithField("pipe", pipe).Info("Created pipe")
	}

	rp.cmd = exec.CommandContext(ctx, path, "--pod", f.Name())
	err = rp.cmd.Start()
	if err != nil {
		return err
	}

	go rp.monitor(ctx)
	go rp.statusUpdater(ctx)
	return nil
}

func writePod(pod *v1.Pod) (f *os.File, err error) {
	f, err = ioutil.TempFile("", "pod")
	err = json.NewEncoder(f).Encode(pod)
	f.Sync()
	f.Close()
	if err != nil {
		return nil, err
	}

	return f, err
}

func (rp *runtimePod) statusUpdater(ctx context.Context) {
	statusPipe, _ := os.OpenFile(backend.GetStatusPipePath(rp.pod), os.O_RDONLY, 0600)
	decoder := json.NewDecoder(statusPipe)
	for {
		pod := v1.Pod{}
		err := decoder.Decode(&pod)
		log.G(ctx).WithField("podStatus", pod.Status).Info("Decoded pod (status)")
		if err != nil {
			rp.cmd.Process.Kill()
			return
		}
		rp.provider.notifier(&pod)
		rp.lock.Lock()
		rp.pod = &pod
		rp.lock.Unlock()
	}
}

func (rp *runtimePod) monitor(ctx context.Context) {
	err := rp.cmd.Wait()
	if err != nil {
		log.G(ctx).WithError(err).Info("RP terminated")
	}

	rp.lock.Lock()
	backend.DestroyStatusPipe(rp.pod)
	if rp.pod.Status.Phase != v1.PodFailed || rp.pod.Status.Phase != v1.PodSucceeded {
		log.G(ctx).Error("TODO: Set pod to failed")
	}
	rp.lock.Unlock()
}

func (rp *runtimePod) delete(ctx context.Context) error {
	rp.lock.Lock()
	defer rp.lock.Unlock()
	rp.killTimer = time.AfterFunc(5 * time.Minute, func() {rp.cmd.Process.Kill()})
	return rp.cmd.Process.Signal(unix.SIGUSR1)
}

func (rp *runtimePod) getPod(ctx context.Context) *v1.Pod {
	rp.lock.Lock()
	defer rp.lock.Unlock()
	return rp.pod
}

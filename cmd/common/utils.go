package common

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

const taskInstanceIDEnvVar = "TITUS_TASK_INSTANCE_ID"

func ReadTaskPodFile(taskID string) (*corev1.Pod, error) {
	if taskID == "" {
		log.Errorf("task ID is empty: can't read pod config file")
		return nil, fmt.Errorf("task ID env var unset: %s", taskInstanceIDEnvVar)
	}

	// This filename is from VK, which is /run/titus-executor/$namespace__$podname/pod.json
	// We only use the default namespace, so we hardcode it here.
	confFile := filepath.Join("/run", "titus-executor", "default__"+taskID, "pod.json")
	contents, err := ioutil.ReadFile(confFile) // nolint: gosec
	if err != nil {
		log.WithError(err).Errorf("Error reading pod config file %s", confFile)
		return nil, err
	}

	var pod corev1.Pod
	if err = json.Unmarshal(contents, &pod); err != nil {
		log.WithError(err).Errorf("Error parsing JSON in pod config file %s", confFile)
		return nil, err
	}

	return &pod, nil
}

// HandleQuitSignal allows us to respond to sigquit, dumping our goroutines like normal, but *not* exit,
// mimicking how java does it.
func HandleQuitSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGQUIT)
	buf := make([]byte, 1<<20)
	for {
		<-sigs
		stacklen := runtime.Stack(buf, true)
		log.Printf("=== received SIGQUIT ===\n*** goroutine dump...\n%s\n*** end\n", buf[:stacklen])
	}
}

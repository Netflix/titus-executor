package common

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	"path/filepath"
)

const taskInstanceIDEnvVar = "TITUS_TASK_INSTANCE_ID"
func ReadTaskPodFile(taskID string) (*corev1.Pod, error) {
	if taskID == "" {
		log.Errorf("task ID is empty: can't read pod config file")
		return nil, fmt.Errorf("task ID env var unset: %s", taskInstanceIDEnvVar)
	}

	// This filename is from VK, which is /run/titus-executor/$namespace__$podname/pod.json
	// We only use the default namespace, so we hardcode it here.
	confFile := filepath.Join("/run/titus-executor/default__"+taskID, "pod.json")
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
package backend

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	"os"
	"syscall"
)

const statusPipeDirName = "executor-status-pipes"

func PodFromFile(file *os.File) (*v1.Pod, error) {
	pod := v1.Pod{}
	err := json.NewDecoder(file).Decode(&pod)
	if err != nil {
		errors.Wrapf(err, "Could not decode pod", file.Name())
	}
	return &pod, nil
}

func GetStatusPipeDir() string {
	return fmt.Sprintf("%s/%s", os.TempDir(), statusPipeDirName)

}

func GetStatusPipePath(pod *v1.Pod) string {
	return fmt.Sprintf("%s/%s", GetStatusPipeDir(), pod.Name)
}

func CreateStatusPipe(pod *v1.Pod) (string, error) {
	pipeDir := GetStatusPipeDir()
	if err := os.MkdirAll(pipeDir, os.ModePerm); err != nil {
		log.Errorf("Failed create status pipe directory: %s", pipeDir)
		return pipeDir, err
	}

	path := GetStatusPipePath(pod)
	if _, err := os.Stat(path); err == nil {
		log.Warnf("Pipe path: %s already exists", path)
		return path, nil
	}

	return path, syscall.Mkfifo(path, 0600)
}

func DestroyStatusPipe(pod *v1.Pod) error {
	path := GetStatusPipePath(pod)
	log.Infof("Destroying status pipe: %s", path)
	return os.RemoveAll(path)
}

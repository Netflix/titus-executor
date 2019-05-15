package backend

import (
	"encoding/json"
	"github.com/pkg/errors"
	"k8s.io/api/core/v1"
	"os"
)


func PodFromFile(file *os.File) (*v1.Pod, error) {
	pod := v1.Pod{}
	err := json.NewDecoder(file).Decode(&pod)
	if err != nil {
		errors.Wrapf(err, "Could not deecode pod", file.Name())
	}
	return &pod, nil
}

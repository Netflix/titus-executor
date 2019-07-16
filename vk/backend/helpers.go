package backend

import (
	"encoding/json"
	"os"

	v1 "k8s.io/api/core/v1"
)

func PodFromFile(file *os.File) (*v1.Pod, error) {
	pod := v1.Pod{}
	err := json.NewDecoder(file).Decode(&pod)
	if err != nil {
		return nil, err
	}
	return &pod, nil
}

package conf

import (
	"os"

	log "github.com/sirupsen/logrus"
)

var (
	// ContainersHome is the location in which the directories with the Task IDs lie, (and under that /logs/...)
	ContainersHome     = "/var/lib/docker/containers/"
	ContainerID        = ""
	RunningInContainer = false
)

func init() {
	loc := os.Getenv("CONTAINER_HOME")
	if loc != "" {
		log.Println("CONTAINER_HOME set: ContainersHome=" + loc)
		ContainersHome = loc
	}

	cID := os.Getenv("TITUS_TASK_ID")
	if cID != "" {
		log.Println("TITUS_TASK_ID set: RunningInContainer=true, ContainerID=" + cID)
		ContainerID = cID
		RunningInContainer = true
		ContainersHome = "/"
	}
}

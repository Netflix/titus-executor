package conf

import (
	"os"

	log "github.com/sirupsen/logrus"
)

var (
	// ContainersHome is the location in which the directories with the Task IDs lie, (and under that /logs/...)
	ContainersHome = "/var/lib/docker/containers/"

	// TitusTaskID initialized using TITUS_TASK_ID from OS environment variable.
	// It can be used as a crude way to determine if this process is running inside a container.
	TitusTaskID = os.Getenv("TITUS_TASK_ID")
)

func init() {
	loc := os.Getenv("CONTAINER_HOME")
	if loc != "" {
		log.Println("Setting $CONTAINER_HOME to " + loc)
		ContainersHome = loc
	}
}

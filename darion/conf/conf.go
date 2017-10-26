package conf

import (
	"os"

	log "github.com/sirupsen/logrus"
)

var (
	// ContainersHome is the location in which the directories with the Task IDs lie, (and under that /logs/...)
	ContainersHome = "/var/lib/docker/containers/"
)

func init() {
	loc := os.Getenv("CONTAINER_HOME")
	if loc != "" {
		log.Println("Setting $CONTAINER_HOME to " + loc)
		ContainersHome = loc
	}
}

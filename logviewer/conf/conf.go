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
	ProxyMode          = true
)

func init() {
	loc := os.Getenv("CONTAINER_HOME")
	if loc != "" {
		ContainersHome = loc
	}

	cID := os.Getenv("TITUS_TASK_ID")
	if cID != "" {
		ContainerID = cID
		RunningInContainer = true
		ContainersHome = "/"
	}

	proxyMode := os.Getenv("DISABLE_PROXY_MODE")
	if proxyMode != "" {
		ProxyMode = false
	}

	log.WithFields(log.Fields{
		"ContainersHome":     ContainersHome,
		"ContainerID":        ContainerID,
		"RunningInContainer": RunningInContainer,
		"ProxyMode":          ProxyMode,
	}).Info("Config loaded")
}

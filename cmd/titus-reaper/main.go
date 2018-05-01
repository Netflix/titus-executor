package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Netflix/titus-executor/logsutil"
	"github.com/Netflix/titus-executor/reaper"
	log "github.com/sirupsen/logrus"
)

var dockerHost string
var debug bool

func main() {
	flag.StringVar(&dockerHost, "docker-host", "unix:///var/run/docker.sock", "Docker Daemon URI")
	flag.BoolVar(&debug, "debug", false, "Turn on debug logging")
	flag.Parse()

	logsutil.MaybeSetupLoggerIfUnderSystemd()
	if debug {
		log.SetLevel(log.DebugLevel)
	}
	path := os.Getenv("PATH")
	if err := os.Setenv("PATH", fmt.Sprintf("%s%s", path, ":/usr/sbin:/sbin:/usr/local/sbin")); err != nil {
		log.Fatal("Unable to set path: ", err)
	}
	reaper.RunReaper(dockerHost)
}

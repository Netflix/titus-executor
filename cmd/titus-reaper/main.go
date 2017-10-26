package main

import (
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/Netflix/titus-executor/logsutil"
	"github.com/Netflix/titus-executor/reaper"
)

var dockerHost string
var debug bool

func init() {
	flag.StringVar(&dockerHost, "docker-host", "unix:///var/run/docker.sock", "Docker Daemon URI")
	flag.BoolVar(&debug, "debug", false, "Turn on debug logging")
	flag.Parse()
}

func main() {
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

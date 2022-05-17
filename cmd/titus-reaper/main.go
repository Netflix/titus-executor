package main

import (
	"context"
	"flag"
	"time"

	"github.com/Netflix/titus-executor/cmd/common"
	"github.com/Netflix/titus-executor/reaper"
	log "github.com/Netflix/titus-executor/utils/log"
	"github.com/sirupsen/logrus"
)

var dockerHost string
var debug bool

func main() {
	go common.HandleQuitSignal()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	flag.StringVar(&dockerHost, "docker-host", "unix:///var/run/docker.sock", "Docker Daemon URI")
	flag.BoolVar(&debug, "debug", false, "Turn on debug logging")
	flag.Parse()

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		log.MaybeSetupLoggerIfOnJournaldAvailable()
	}

	err := reaper.RunReaper(ctx, dockerHost)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to run repear")
	}
	time.Sleep(100 * time.Millisecond)
}

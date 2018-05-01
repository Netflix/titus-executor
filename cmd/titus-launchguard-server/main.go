package main

import (
	"context"
	"flag"
	"net/http"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/launchguard/server"
	"github.com/Netflix/titus-executor/logsutil"
	log "github.com/sirupsen/logrus"
)

var debug bool

func main() {
	flag.BoolVar(&debug, "debug", false, "Turn on debug logging")
	flag.Parse()

	ctx := context.Background()
	logsutil.MaybeSetupLoggerIfUnderSystemd()
	if debug {
		log.SetLevel(log.DebugLevel)
	}

	m := metrics.New(ctx, log.StandardLogger(), nil)
	if err := http.ListenAndServe(":8006", server.NewLaunchGuardServer(m)); err != nil {
		log.Error("Error: HTTP ListenAndServe: ", err)
	}
}

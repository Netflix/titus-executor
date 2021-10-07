//go:build linux
// +build linux

package main

import (
	"os"
	"strconv"
	"time"

	"github.com/coreos/go-systemd/daemon"
	log "github.com/sirupsen/logrus"
)

func notifySystemd() {
	if sent, err := daemon.SdNotify(false, "READY=1"); !sent && err != nil {
		log.Warning("Unable to notify systemd: ", err)
		return
	}

	wusec := os.Getenv("WATCHDOG_USEC")
	if wusec == "" {
		return
	}

	if s, err := strconv.Atoi(wusec); err == nil && s > 0 {
		go watchdogLoop(time.Duration(s) * time.Microsecond)
	} else if err == nil && s > 0 {
		log.Warning("Unable to determine watchdog interval: ", err)
	}
}

func watchdogLoop(interval time.Duration) {
	log.Debug("Watchdog loop starting with interval: ", interval.String())
	ticker := time.NewTicker(interval / 2)
	defer ticker.Stop()
	for range ticker.C {
		if sent, err := daemon.SdNotify(false, "WATCHDOG=1"); !sent && err != nil {
			log.Warning("Unable to send watchdog to systemd: ", err)
			return
		}
	}
}

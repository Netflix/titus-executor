// +build linux

package logsutil

import (
	"github.com/coreos/go-systemd/util"
	log "github.com/sirupsen/logrus"
	"github.com/wercker/journalhook"
)

// MaybeSetupLoggerIfUnderSystemd sets up journald logging if running as a systemd unit
func MaybeSetupLoggerIfUnderSystemd() {
	if runningFromSystemService, err := util.RunningFromSystemService(); runningFromSystemService {
		journalhook.Enable()
	} else if err != nil {
		log.Error("Error checking if running under systemd unit: ", err)
	}

}

// MaybeSetupLoggerIfOnJournaldAvailable sets up journald logging if the system
func MaybeSetupLoggerIfOnJournaldAvailable() {
	journalhook.Enable()
}

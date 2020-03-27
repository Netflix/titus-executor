// +build linux

package utils

import (
	"github.com/wercker/journalhook"
)

// MaybeSetupLoggerIfOnJournaldAvailable sets up journald logging if the system
func MaybeSetupLoggerIfOnJournaldAvailable() {
	journalhook.Enable()
}

// +build !linux

package logsutil

// MaybeSetupLoggerIfUnderSystemd sets up journald logging if running as a systemd unit
func MaybeSetupLoggerIfUnderSystemd() {

}

// MaybeSetupLoggerIfOnJournaldAvailable sets up journald logging if the system
func MaybeSetupLoggerIfOnJournaldAvailable() {
}

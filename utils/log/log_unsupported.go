//go:build !linux
// +build !linux

package log

// MaybeSetupLoggerIfOnJournaldAvailable sets up journald logging if the system
func MaybeSetupLoggerIfOnJournaldAvailable() {
}

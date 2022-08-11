//go:build !linux
// +build !linux

package reaper

func checkIfFuseWedgedPidNs(pid int, taskID string) {
}

package titusdriver

import (
	"strconv"
)

// TitusTaskState represents the current state of a task
type TitusTaskState uint32

// Possible Task states
const (
	Starting TitusTaskState = iota
	Running
	Finished // successfully
	Failed   // terminated by itself
	Killed   // stopped by request
	Lost     // terminated because of us
)

func (s TitusTaskState) String() string {
	switch s {
	case Starting:
		return "TASK_STARTING"
	case Running:
		return "TASK_RUNNING"
	case Finished:
		return "TASK_FINISHED"
	case Failed:
		return "TASK_FAILED"
	case Killed:
		return "TASK_KILLED"
	case Lost:
		return "TASK_LOST"
	default:
		return strconv.FormatUint(uint64(s), 10)
	}
}

// IsTerminalStatus indicates whether or not a given status is the last status a task should end up in
func (s TitusTaskState) IsTerminalStatus() bool {
	// IsTerminalState returns true if the task status is a terminal state
	switch s {
	case Finished:
	case Failed:
	case Killed:
	case Lost:
	default:
		return false
	}
	return true
}

package testdriver

import (
	"time"

	titusdriver "github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/runner"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	log "github.com/sirupsen/logrus"
)

// TaskStatus describes a particular task's status
type TaskStatus struct {
	TaskID    string
	Status    string
	Msg       string
	Details   *runtimeTypes.Details
	Timestamp time.Time
}

// TitusTestDriver wraps the executor for integration with unit tests
type TitusTestDriver struct {
	// StatusChannel produces status for all tasks of the driver's executor
	StatusChannel chan TaskStatus
}

// New allocates and initializes a TitusTestDriver and sets the driver in the executor
func New(r *runner.Runner) (*TitusTestDriver, error) {
	driver := &TitusTestDriver{
		StatusChannel: make(chan TaskStatus, 10),
	}
	go func() {
		for update := range r.UpdatesChan {
			driver.ReportTitusTaskStatus(update.TaskID, update.Mesg, update.State, update.Details)
		}
	}()
	return driver, nil
}

// ReportTitusTaskStatus notifies a test via a channel about a task's state
func (driver *TitusTestDriver) ReportTitusTaskStatus(taskID string, msg string, state titusdriver.TitusTaskState, details *runtimeTypes.Details) {
	log.Printf("Sending task status for task %s, state %s, and message %s", taskID, state.String(), msg)
	driver.StatusChannel <- TaskStatus{TaskID: taskID, Status: state.String(), Msg: msg, Details: details, Timestamp: time.Now()}
}

package testdriver

import (
	log "github.com/sirupsen/logrus"
	"github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/runtime"
)

// TaskStatus describes a particular task's status
type TaskStatus struct {
	TaskID string
	Status string
}

// TitusTestDriver wraps the executor for integration with unit tests
type TitusTestDriver struct {
	// StatusChannel produces status for all tasks of the driver's executor
	StatusChannel chan TaskStatus
}

// New allocates and initializes a TitusTestDriver and sets the driver in the executor
func New(executor titusdriver.TitusExecutor) (*TitusTestDriver, error) {
	driver := &TitusTestDriver{
		StatusChannel: make(chan TaskStatus, 10),
	}
	executor.SetTitusDriver(driver)
	return driver, nil
}

// ReportTitusTaskStatus notifies a test via a channel about a task's state
func (driver *TitusTestDriver) ReportTitusTaskStatus(taskID string, msg string, state titusdriver.TitusTaskState, details *runtime.Details) {
	log.Printf("Sending task status for task %s, state %s, and message %s", taskID, state.String(), msg)
	driver.StatusChannel <- TaskStatus{TaskID: taskID, Status: state.String()}
}

package gc3

type State struct {
	Frameworks []Framework `json:"frameworks"`
}

type Framework struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Executors []Executor `json:"executors"`
}

type Executor struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	ExecutorID string `json:"executor_id"`
	SlaveID    string `json:"slave_id"`
	Tasks      []Task `json:"tasks"`
}

// Task holds a task as defined in the /state Mesos HTTP endpoint.
type Task struct {
	FrameworkID string `json:"framework_id"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	SlaveID     string `json:"slave_id"`
	State       string `json:"state"`
}

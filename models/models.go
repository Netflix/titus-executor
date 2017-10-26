package models

// CurrentState data structure that is exposed in get-current-state endpoint
type CurrentState struct {
	Tasks map[string]string
}

const (
	// ExecutorPidLabel is the executor's os.Getpid()
	ExecutorPidLabel = "titus.executor.pid"
	// ExecutorHTTPListenerAddressLabel is the IP:Port that the ephemeral HTTP listener is working on
	ExecutorHTTPListenerAddressLabel = "titus.executor.http.listener.address"
	// TaskIDLabel is the The canonical TASK ID
	TaskIDLabel = "titus.task_id"
	// NetworkContainerIDLabel is the container ID of the network pod
	NetworkContainerIDLabel = "titus.network_container_id"
)

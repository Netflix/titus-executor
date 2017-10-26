package reaper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/models"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	log "github.com/sirupsen/logrus"
)

func newContainer(executorHTTPListenerAddress, executorPid, taskIDLabel string) types.ContainerJSON {
	return types.ContainerJSON{
		Config: &container.Config{
			Labels: map[string]string{
				models.TaskIDLabel:                      taskIDLabel,
				models.ExecutorPidLabel:                 executorPid,
				models.ExecutorHTTPListenerAddressLabel: executorHTTPListenerAddress,
			},
		},
	}
}

func wireUpHandlerShouldNeverBeHit(t *testing.T) http.Handler {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/get-current-state", func(resp http.ResponseWriter, req *http.Request) {
		t.Fatal("Handler should never be hit")
	})
	return serveMux
}

func wireUpHandler(cs *models.CurrentState, t *testing.T) http.Handler {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/get-current-state", func(resp http.ResponseWriter, req *http.Request) {
		resp.WriteHeader(200)
		if err := json.NewEncoder(resp).Encode(cs); err != nil {
			t.Fatal("Handler not working: ", err)
		}
	})
	return serveMux
}
func wireUpUnresponsiveHandler() http.Handler {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/get-current-state", func(resp http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		select {
		case <-ctx.Done():
		case <-time.After(time.Second * 10):
		}
	})
	return serveMux
}

func TestReaperOneContainerUnhealthyExecutor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()
	server := httptest.NewServer(wireUpUnresponsiveHandler())
	defer server.CloseClientConnections()
	defer server.Close()

	server.Config.WriteTimeout = time.Second * 10
	server.Config.ReadTimeout = time.Second * 10

	container := newContainer(server.Listener.Addr().String(), strconv.Itoa(os.Getpid()), "test-task-id")
	if !shouldTerminate(ctx, log.NewEntry(log.New()), container, newHTTPClient()) {
		t.Fatal("Did not terminate container with unresponsive HTTP handler")
	}
}

func TestReaperOneContainerMissingExecutor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()
	server := httptest.NewServer(wireUpHandlerShouldNeverBeHit(t))
	defer server.CloseClientConnections()
	defer server.Close()

	container := newContainer(server.Listener.Addr().String(), "0", "test-task-id")
	if !shouldTerminate(ctx, log.NewEntry(log.New()), container, newHTTPClient()) {
		t.Fatal("Did not terminate container with missing executor")
	}
}

func TestReaperOneContainersNoCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const testTaskID = "test-task-id"
	currentState := &models.CurrentState{
		Tasks: map[string]string{
			testTaskID: "TASK_RUNNING",
		},
	}

	server := httptest.NewServer(wireUpHandler(currentState, t))
	defer server.CloseClientConnections()
	defer server.Close()

	container := newContainer(server.Listener.Addr().String(), strconv.Itoa(os.Getpid()), testTaskID)
	if shouldTerminate(ctx, log.NewEntry(log.New()), container, newHTTPClient()) {
		t.Fatal("Terminated task")
	}
}

func TestIsPidAlive(t *testing.T) {
	if !isPidAlive(strconv.Itoa(os.Getpid())) {
		t.Fail()
	}
	if isPidAlive("0") {
		t.Fail()
	}

}

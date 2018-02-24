package reaper

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/Netflix/titus-executor/models"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	log "github.com/sirupsen/logrus"
)

func newContainer(executorPid, taskIDLabel string) types.ContainerJSON {
	return types.ContainerJSON{
		Config: &container.Config{
			Labels: map[string]string{
				models.TaskIDLabel:      taskIDLabel,
				models.ExecutorPidLabel: executorPid,
			},
		},
	}
}

func TestReaperOneContainerMissingExecutor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	container := newContainer("0", "test-task-id")
	if !shouldTerminate(ctx, log.NewEntry(log.New()), container) {
		t.Fatal("Did not terminate container with missing executor")
	}
}

func TestReaperOneContainersNoCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const testTaskID = "test-task-id"

	container := newContainer(strconv.Itoa(os.Getpid()), testTaskID)
	if shouldTerminate(ctx, log.NewEntry(log.New()), container) {
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

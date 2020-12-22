package reaper

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"github.com/Netflix/titus-executor/models"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
)

type testClient struct {
	stopError   error
	removeError error
	stops       int
	removes     int
}

func (t *testClient) ContainerStop(ctx context.Context, containerID string, timeout *time.Duration) error {
	t.stops++
	return t.stopError
}

func (t *testClient) ContainerRemove(ctx context.Context, container string, options types.ContainerRemoveOptions) error {
	t.removes++
	return t.removeError
}

func TestNoTerminate(t *testing.T) {
	if os := runtime.GOOS; os != "linux" {
		t.Skipf("OS %q not supported to test", os)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	container := types.ContainerJSON{
		Config: &container.Config{
			Labels: map[string]string{
				models.TaskIDLabel:      "test-task-id",
				models.ExecutorPidLabel: strconv.Itoa(os.Getpid()),
			},
		},
	}

	fakeClient := &testClient{}
	assert.ErrorContains(t, processContainerJSON(ctx, container, fakeClient), "Could not determine")
	assert.Assert(t, is.Equal(fakeClient.removes, 0))
	assert.Assert(t, is.Equal(fakeClient.stops, 0))
}

func TestTerminate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	container := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: "foo",
		},
		Config: &container.Config{
			Labels: map[string]string{
				models.TaskIDLabel:      "test-task-id",
				models.ExecutorPidLabel: "-1",
			},
		},
	}

	fakeClient := &testClient{}
	assert.NilError(t, processContainerJSON(ctx, container, fakeClient))
	assert.Assert(t, is.Equal(fakeClient.removes, 1))
	assert.Assert(t, is.Equal(fakeClient.stops, 1))
}

func TestTerminateFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	container := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: "foo",
		},
		Config: &container.Config{
			Labels: map[string]string{
				models.TaskIDLabel:      "test-task-id",
				models.ExecutorPidLabel: "-1",
			},
		},
	}

	fakeClient := &testClient{
		stopError:   errors.New("stopError"),
		removeError: errors.New("removeError"),
	}
	err := processContainerJSON(ctx, container, fakeClient)
	assert.ErrorContains(t, err, "stopError")
	assert.ErrorContains(t, err, "removeError")

	assert.Assert(t, is.Equal(fakeClient.removes, 1))
	assert.Assert(t, is.Equal(fakeClient.stops, 1))
}

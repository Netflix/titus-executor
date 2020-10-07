package standalone

import (
	"context"
	"errors"

	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
)

const gpuTestRuntime = "fake-gpu-runtime"

var (
	_ runtimeTypes.GPUManager = (*gpuManager)(nil)
	_ runtimeTypes.GPUManager = (*dummyGPUManager)(nil)
)

type dummyGPUManager struct{}

func (d *dummyGPUManager) AllocDevices(ctx context.Context, n int) (runtimeTypes.GPUContainer, error) {
	return nil, errors.New("This is the dummy GPU manager. Not meant to be used")
}

func (d *dummyGPUManager) Runtime() string {
	panic("Should never be called")
}

// Fake GPU Manager
type gpuManager struct {
	devicesAllocated   int
	devicesDeallocated int
}

type gpuContainer struct {
	m       *gpuManager
	devices int
}

func (g *gpuContainer) Env() map[string]string {
	return nil
}

func (g *gpuContainer) Devices() []string {
	ret := make([]string, g.devices)
	for i := 0; i < g.devices; i++ {
		ret[i] = "/dev/null"
	}
	return ret
}

func (g *gpuContainer) Deallocate() int {
	if g.m.devicesDeallocated == 0 {
		g.m.devicesDeallocated += g.devices
	}
	return g.devices
}

func (g *gpuContainer) Runtime() string {
	return gpuTestRuntime
}

func (g *gpuManager) AllocDevices(ctx context.Context, n int) (runtimeTypes.GPUContainer, error) {
	g.devicesAllocated = +n
	return &gpuContainer{
		m:       g,
		devices: n,
	}, nil
}

package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
)

func TestNewBehaviorOf(t *testing.T) {
	behavior, err := NewBehaviorOf("delay=10m; jitter=30s; status=StatusFinished; message=Simulated failure")
	require.True(t, behavior != nil)
	require.True(t, err == nil)
	require.True(t, *behavior == Behavior{
		Delay:           10 * time.Minute,
		Jitter:          30 * time.Second,
		ExecutionStatus: runtimeTypes.StatusFinished,
		Message:         "Simulated failure",
	})
}

func Test_Jitter(t *testing.T) {
	behavior, _ := NewBehaviorOf("delay=10m; jitter=30s")
	delay := behavior.DelayWithJitter()
	require.GreaterOrEqual(t, delay, 10*time.Minute-30*time.Second)
	require.LessOrEqual(t, delay, 10*time.Minute+30*time.Second)
}

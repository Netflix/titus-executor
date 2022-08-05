package main

import (
	"fmt"
	"github.com/pkg/errors"
	"math/rand"
	"strings"
	"time"

	coreV1 "k8s.io/api/core/v1"

	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
)

// Simulated behavior of a pod at each lifecycle state.
// Syntax:
//   commands=<delay_duration> | (command (";" command)*)
//   command=cmd_name "=" cmd_value
//   cmd_name=("delay"|"jitter"|"status"|"message")
//   cmd_value=[^;]+

const (
	commandDelay   = "delay"
	commandJitter  = "jitter"
	commandStatus  = "status"
	commandMessage = "message"

	prepareTime = "github.com.netflix.titus.executor/prepareTime"
	runTime     = "github.com.netflix.titus.executor/runTime"
	killTime    = "github.com.netflix.titus.executor/killTime"
)

var (
	defaultPrepareStateBehavior = Behavior{
		Delay:  time.Second,
		Jitter: 0,
	}
	defaultRunStateBehavior = Behavior{
		Delay:           time.Hour,
		Jitter:          30 * time.Minute,
		ExecutionStatus: runtimeTypes.StatusFinished,
		Message:         "mockVM container completed",
	}
	defaultKillStateBehavior = Behavior{
		Delay:  time.Second,
		Jitter: 0,
	}
)

type Behavior struct {
	Delay           time.Duration
	Jitter          time.Duration
	ExecutionStatus runtimeTypes.Status
	Message         string
}

func NewBehaviorOf(spec string) (*Behavior, error) {
	// Short version (just duration)
	if delay, err := time.ParseDuration(spec); err == nil {
		return &Behavior{Delay: delay}, nil
	}
	return parseCommands(spec)
}

func NewBehaviorOfOrDefault(spec string, defaultBehavior Behavior) Behavior {
	if spec == "" {
		return defaultBehavior
	}
	if behavior, err := NewBehaviorOf(spec); err != nil {
		defaultBehavior.Message = err.Error()
		return defaultBehavior
	} else {
		return *behavior
	}
}

func NewPrepareStateBehavior(pod *coreV1.Pod) Behavior {
	return NewBehaviorOfOrDefault(pod.Annotations[prepareTime], defaultPrepareStateBehavior)
}

func NewRunStateBehavior(pod *coreV1.Pod) Behavior {
	behavior := NewBehaviorOfOrDefault(pod.Annotations[runTime], defaultRunStateBehavior)
	if behavior.ExecutionStatus == runtimeTypes.StatusUnknown {
		behavior.ExecutionStatus = runtimeTypes.StatusFinished
	}
	if behavior.Message == "" {
		behavior.Message = "Successful execution"
	}
	return behavior
}

func NewKillStateBehavior(pod *coreV1.Pod) Behavior {
	return NewBehaviorOfOrDefault(pod.Annotations[killTime], defaultKillStateBehavior)
}

func (b Behavior) String() string {
	return fmt.Sprintf("%#v", b)
}

func (b *Behavior) DelayWithJitter() time.Duration {
	if b.Jitter == 0 {
		return b.Delay
	}
	var delayJitterMs = (rand.Float64() - 0.5) * float64(2*b.Jitter.Milliseconds())
	return b.Delay + time.Duration(int64(delayJitterMs))*time.Millisecond
}

func parseCommands(spec string) (*Behavior, error) {
	behavior := Behavior{}
	cmdParts := strings.Split(spec, ";")
	for _, cmdPart := range cmdParts {
		key, value, err := splitCommand(cmdPart)
		if err != nil {
			return nil, err
		}
		if key == commandDelay {
			if delay, err := time.ParseDuration(value); err != nil {
				return nil, errors.New("invalid duration value")
			} else {
				behavior.Delay = delay
			}
		} else if key == commandJitter {
			if delay, err := time.ParseDuration(value); err != nil {
				return nil, errors.New("invalid jitter value")
			} else {
				behavior.Jitter = delay
			}
		} else if key == commandStatus {
			switch value {
			case "StatusUnknown":
				behavior.ExecutionStatus = runtimeTypes.StatusUnknown
			case "StatusRunning":
				behavior.ExecutionStatus = runtimeTypes.StatusRunning
			case "StatusFinished":
				behavior.ExecutionStatus = runtimeTypes.StatusFinished
			case "StatusFailed":
				behavior.ExecutionStatus = runtimeTypes.StatusFailed
			default:
				return nil, errors.New("invalid status")
			}
		} else if key == commandMessage {
			behavior.Message = value
		} else {
			return nil, errors.New("unrecognized command: " + key)
		}
	}
	return &behavior, nil
}

func splitCommand(command string) (string, string, error) {
	idx := strings.Index(command, "=")
	if idx < 0 {
		return "", "", errors.New("<command_name>=<command_value> expected")
	}
	key := strings.TrimSpace(command[0:idx])
	value := strings.TrimSpace(command[idx+1:])
	if key == "" {
		return "", "", errors.New("command name not provided")
	}
	return key, value, nil
}

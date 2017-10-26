package circuit

import (
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

type state func() state

const (
	// ShortCircuitForeverEnv is a special environment variable, if set -- SHORT_CIRCUIT_QUITELITE=true, will trigger state 1
	ShortCircuitForeverEnv = "SHORT_CIRCUIT_QUITELITE"
)

func isShortCircuitedForEver() bool {
	val := os.Getenv(ShortCircuitForeverEnv)
	if val == "" {
		return false
	}
	ret, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}
	return ret
}

// Circuit is a circuit-breaker pattern FSM
// It has three modes:
// 1. Short-circuit (stay permanently short-circuited)
// 2. Temporarily short-circuit (stay short-circuited for some period)
// 3. Do not be short-circuited
type Circuit struct {
	shortCircuitChan       chan struct{}
	shortCircuitForever    chan struct{}
	deactivateShortCircuit chan struct{}
	shortCircuitFor        chan time.Duration
	shortCircuited         int32
}

// NewCircuit must be called to get a circuit, otherwise the internal structures wont be initialized correctly
func NewCircuit() *Circuit {
	c := &Circuit{
		shortCircuitChan:       make(chan struct{}),
		shortCircuitForever:    make(chan struct{}),
		shortCircuitFor:        make(chan time.Duration),
		deactivateShortCircuit: make(chan struct{}),
	}

	go c.loop()

	return c
}

// ShortCircuitChan gets a channel - if you can read off of it at a given time, you're in short-circuit mode
func (c *Circuit) ShortCircuitChan() chan struct{} {
	return c.shortCircuitChan
}

// ShortCircuitForever puts the FSM into short-circuit forever
func (c *Circuit) ShortCircuitForever() {
	c.shortCircuitForever <- struct{}{}
}

// ShortCircuited is an alternate API which allows you to know about instaneous short circuits
// It can lag behind slightly.
func (c *Circuit) ShortCircuited() bool {
	return atomic.LoadInt32(&c.shortCircuited) == 1
}

// ShortCircuitForDuration puts the FSM into a short-circuit state for some duration, d, unless shortCircuitForever is called
func (c *Circuit) ShortCircuitForDuration(d time.Duration) {
	c.shortCircuitFor <- d
}

func (c *Circuit) loop() {
	currentState := c.notShortcircuited
	if isShortCircuitedForEver() {
		currentState = c.shortCircuitedForever
	}
	for {
		currentState = currentState()
	}
}

func (c *Circuit) notShortcircuited() state {
	atomic.StoreInt32(&c.shortCircuited, 0)
	select {
	case <-c.shortCircuitForever:
		return c.shortCircuitedForever
	case d := <-c.shortCircuitFor:
		time.AfterFunc(d, func() {
			/*
				This should never block
			*/

			c.deactivateShortCircuit <- struct{}{}
		})
		return c.shortCircuitedForDuration
	}
}

func (c *Circuit) shortCircuitedForever() state {
	atomic.StoreInt32(&c.shortCircuited, 1)
	select {
	case <-c.shortCircuitForever:
	case <-c.shortCircuitFor:
		/* This is a noop, we don't care */
	case <-c.deactivateShortCircuit:
		/*
			This channel is only meant to be used as a mechanism to deactivate short-circuiting after some time period has passed
			Once in short-circuit forever, we ignore it
		*/
	case c.shortCircuitChan <- struct{}{}:
	}
	return c.shortCircuitedForever
}

func (c *Circuit) shortCircuitedForDuration() state {
	atomic.StoreInt32(&c.shortCircuited, 1)
	select {
	case <-c.deactivateShortCircuit:
		return c.notShortcircuited
	case <-c.shortCircuitForever:
		return c.shortCircuitedForever
	case <-c.shortCircuitFor:
		/* This is a noop, we don't care, we might want to log this? */
	case c.shortCircuitChan <- struct{}{}:
		return c.notShortcircuited
	}
	return c.shortCircuitedForDuration
}

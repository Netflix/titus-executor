package ec2wrapper

import (
	"testing"
	"time"

	"gotest.tools/assert"
)

func TestEC2Timer(t *testing.T) {
	t.Parallel()
	nt := newTimer()
	now := time.Now()
	nt.setDeadline(3 * time.Second)
	// This should wait at least 3 seconds to trigger
	<-nt.c
	assert.Assert(t, time.Since(now) > 3*time.Second)
}

func TestEC2TimerDontGrow(t *testing.T) {
	t.Parallel()
	nt := newTimer()
	now := time.Now()
	nt.setDeadline(3 * time.Second)
	nt.setDeadline(30 * time.Second)
	// This should wait at least 3 seconds to trigger
	<-nt.c
	assert.Assert(t, time.Since(now) > 3*time.Second)
	assert.Assert(t, time.Since(now) < 10*time.Second)

}

func TestEC2TimerShrink(t *testing.T) {
	t.Parallel()
	nt := newTimer()
	now := time.Now()
	nt.setDeadline(3 * time.Second)
	nt.setDeadline(100 * time.Millisecond)
	// This should wait at least 3 seconds to trigger
	<-nt.c
	assert.Assert(t, time.Since(now) < 1*time.Second)
}

package ec2wrapper

import "time"

type timer struct {
	stopCh   chan struct{}
	c        chan struct{}
	timer    *time.Timer
	deadline time.Time
}

// NewTimer returns a "timer" which will never fire until a deadline is set
// IT IS NOT THREAD SAFE
func newTimer() *timer {
	return &timer{
		stopCh: make(chan struct{}),
		c:      make(chan struct{}),
	}
}

// This is a special timer. If the current deadline (derived by now + duration), is closer
// than the last deadline (by default infinity), then it updates the deadline to be that smaller
// number
func (t *timer) setDeadline(duration time.Duration) {
	if t.timer == nil {
		t.timer = time.NewTimer(duration)
		t.deadline = time.Now().Add(duration)
		go func() {
			defer t.timer.Stop()
			select {
			case <-t.timer.C:
			case <-t.stopCh:
			}
			t.c <- struct{}{}
		}()
		return
	}

	if time.Until(t.deadline) > duration {
		t.timer.Reset(duration)
		t.deadline = time.Now().Add(duration)
	}
}

// stop cleans up the goroutine that's activated when setDeadline is called
func (t *timer) stop() {
	close(t.stopCh)
}

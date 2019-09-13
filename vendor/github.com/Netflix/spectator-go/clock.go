package spectator

import "time"

type Clock interface {
	Now() time.Time
	Nanos() int64
}

type SystemClock struct{}

func (c *SystemClock) Now() time.Time {
	return time.Now()
}

func (c *SystemClock) Nanos() int64 {
	now := time.Now()
	return now.UnixNano()
}

type ManualClock struct {
	nanos int64
}

func (c *ManualClock) Now() time.Time {
	return time.Unix(0, c.nanos)
}

func (c *ManualClock) Nanos() int64 {
	return c.nanos
}

func (c *ManualClock) SetFromDuration(duration time.Duration) {
	c.nanos = int64(duration)
}

func (c *ManualClock) SetNanos(nanos int64) {
	c.nanos = nanos
}

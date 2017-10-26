package metrics

import (
	"time"
)

// Logger allow clients to use whatever log library they need
type Logger interface {
	Println(v ...interface{})
	Printf(format string, v ...interface{})
}

// Reporter asynchronously sends metrics to Atlas. Operations may block while metrics are being flushed
type Reporter interface {
	// Counter asynchronously records a counter for later pushing to Atlas
	Counter(name string, value int, tags map[string]string)
	// Gauge asynchronously records a counter for later pushing to Atlas
	Gauge(name string, value int, tags map[string]string)
	// Timer asynchronously records a duration for later pushing to Atlas
	Timer(name string, value time.Duration, tags map[string]string)
	// Flush blocks and forces pending metrics to be sent
	Flush()
}

// Discard is a reporter that does nothing. It is useful in testing, or when metrics need to be disabled.
var Discard Reporter = &noop{}

type noop struct{}

func (*noop) Flush()                                                         {}
func (*noop) Counter(name string, value int, tags map[string]string)         {}
func (*noop) Gauge(name string, value int, tags map[string]string)           {}
func (*noop) Timer(name string, value time.Duration, tags map[string]string) {}

type counter struct {
	Timestamp int64             `json:"timestamp"`
	Type      string            `json:"type"`
	Name      string            `json:"name"`
	Tags      map[string]string `json:"tags"`
	Value     uint64            `json:"value"`
}

type gauge struct {
	Timestamp int64             `json:"timestamp"`
	Type      string            `json:"type"`
	Name      string            `json:"name"`
	Tags      map[string]string `json:"tags"`
	Value     uint64            `json:"value"`
}

type timer struct {
	Timestamp int64             `json:"timestamp"`
	Type      string            `json:"type"`
	Name      string            `json:"name"`
	Tags      map[string]string `json:"tags"`
	Value     uint64            `json:"value"`
}

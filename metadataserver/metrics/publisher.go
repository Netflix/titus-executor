package metrics

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"context"

	atlasMetrics "github.com/Netflix/metrics-client-go/metrics"
)

var reporter = atlasMetrics.New(context.Background(), log.New(), map[string]string{})

// A simple metrics publisher wrapper

// StopWatch is used to measure durations
type StopWatch struct {
	st int64
}

// NewStopWatch initializes a Stopwatch with the current time
func NewStopWatch() *StopWatch {
	return &StopWatch{st: time.Now().UnixNano()}
}

// Reset sets the stopwatch to the current time
func (sw *StopWatch) Reset() {
	sw.st = time.Now().UnixNano()
}

// GetDelta returns the time elapsed since the time the stopwatch was set
func (sw *StopWatch) GetDelta() time.Duration {
	return time.Duration(time.Now().UnixNano() - sw.st)
}

// Publish sends the current state of the stopwatch to Atlas
func (sw *StopWatch) Publish(name string) {
	PublishTimer(name, sw.GetDelta())
}

// MetricsPublisherDisabled short circuits publishing to Atlas
var MetricsPublisherDisabled = false

const metricsPrefix = "titus.metadata.service"

func metricName(name string) string {
	return fmt.Sprintf("%s.%s", metricsPrefix, name)
}

// DefaultTags are automatically added to all published metrics
var DefaultTags = map[string]string{}

// PublishCounter creates, and pushes a counter to Atlas with a specific value
func PublishCounter(name string, tags map[string]string, value int) {
	if MetricsPublisherDisabled {
		return
	}

	reporter.Counter(metricName(name), value, tags)
}

// PublishIncrementCounter creates, and pushes a counter to Atlas with a value of 1
func PublishIncrementCounter(name string) {
	PublishCounter(name, DefaultTags, 1)
}

// PublishGaugeWithTags creates, and pushes a gauge to Atlas with specific tags
func PublishGaugeWithTags(name string, value int, tags map[string]string) {
	if MetricsPublisherDisabled {
		return
	}

	reporter.Gauge(metricName(name), value, tags)
}

// PublishGauge creates, and pushes a gauge to Atlas with default tags
func PublishGauge(name string, value int) {
	PublishGaugeWithTags(name, value, nil)
}

// PublishTimerWithTags creates, and pushes a timer to Atlas with specific tags
func PublishTimerWithTags(name string, value time.Duration, tags map[string]string) {
	if MetricsPublisherDisabled {
		return
	}

	reporter.Timer(metricName(name), value, tags)
}

// PublishTimer creates, and pushes a gauge to Atlas with default tags
func PublishTimer(name string, value time.Duration) {
	PublishTimerWithTags(name, value, DefaultTags)
}

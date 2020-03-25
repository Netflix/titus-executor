package runner

import (
	"testing"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/stretchr/testify/assert"
)

func TestEmptyDefaultTags(t *testing.T) {
	reporter := NewReporter(metrics.Discard)
	myTagger, ok := reporter.(tagger)

	assert.True(t, ok)
	assert.Empty(t, myTagger.tags(nil))
	assert.Empty(t, myTagger.tags(map[string]string{}))
}

func TestDefaultTags(t *testing.T) {
	reporter := NewReporter(metrics.Discard)
	myTagger, ok := reporter.(tagger)
	assert.True(t, ok)

	myTagger.append(map[string]string{"foo": "1"})
	myTagger.append(map[string]string{"bar": "2"})

	assert.Equal(t, map[string]string{"foo": "1", "bar": "2"}, myTagger.tags(nil))
}

func TestMergeTags(t *testing.T) {
	reporter := NewReporter(metrics.Discard)
	myTagger, ok := reporter.(tagger)
	assert.True(t, ok)

	myTagger.append(map[string]string{"foo": "1"})

	assert.Equal(t, map[string]string{"foo": "1", "bar": "2"}, myTagger.tags(map[string]string{"bar": "2"}))
}

func TestOverrideTags(t *testing.T) {
	reporter := NewReporter(metrics.Discard)
	myTagger, ok := reporter.(tagger)
	assert.True(t, ok)

	myTagger.append(map[string]string{"foo": "1", "bar": "2"})

	assert.Equal(t, map[string]string{"foo": "3", "bar": "2"}, myTagger.tags(map[string]string{"foo": "3"}))
}

type mockReporter struct {
	timerCount   int
	counterCount int
	gaugeCount   int
}

func (r *mockReporter) Flush()                                                 {}
func (r *mockReporter) Counter(name string, value int, tags map[string]string) { r.counterCount++ }
func (r *mockReporter) Gauge(name string, value int, tags map[string]string)   { r.gaugeCount++ }
func (r *mockReporter) Timer(name string, value time.Duration, tags map[string]string) {
	r.timerCount++
}

// TestDelegate verifies that the embedded delegate is invoked
func TestDelegate(t *testing.T) {
	mockReporterStruct := mockReporter{}
	reporter := NewReporter(&mockReporterStruct)

	reporter.Counter("foo", 1, nil)
	assert.Equal(t, 1, mockReporterStruct.counterCount)

	reporter.Timer("foo", 1, nil)
	reporter.Timer("foo", 1, nil)
	assert.Equal(t, mockReporterStruct.timerCount, 2)

	reporter.Gauge("foo", 1, nil)
	reporter.Gauge("foo", 1, nil)
	reporter.Gauge("foo", 1, nil)
	assert.Equal(t, mockReporterStruct.gaugeCount, 3)
}

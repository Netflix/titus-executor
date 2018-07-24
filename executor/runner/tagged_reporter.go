package runner

import (
	"sync"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
)

// tagger interface exposes external management of default tags
type tagger interface {
	// append to list of tags
	append(tags map[string]string)
	// tags returns a merged list of tags from input and default
	tags(tags map[string]string) map[string]string
}

// reporter wraps metrics.Reporter and implements tagger interface
// that internally manages default tags applied to subsequent metrics operations.
type reporter struct {
	metrics     metrics.Reporter
	defaultTags *sync.Map
}

// NewReporter returns a Reporter that implements the tagger interface
func NewReporter(metrics metrics.Reporter) metrics.Reporter {
	return &reporter{
		metrics:     metrics,
		defaultTags: &sync.Map{},
	}
}

// Counter asynchronously records a counter for later pushing to Atlas
func (r *reporter) Counter(name string, value int, tags map[string]string) {
	mergedTags := r.tags(tags)
	r.metrics.Counter(name, value, mergedTags)
}

// Gauge asynchronously records a counter for later pushing to Atlas
func (r *reporter) Gauge(name string, value int, tags map[string]string) {
	mergedTags := r.tags(tags)
	r.metrics.Gauge(name, value, mergedTags)
}

// Timer asynchronously records a duration for later pushing to Atlas
func (r *reporter) Timer(name string, value time.Duration, tags map[string]string) {
	mergedTags := r.tags(tags)
	r.metrics.Timer(name, value, mergedTags)
}

// Flush blocks and forces pending metrics to be sent
func (r *reporter) Flush() {
	r.metrics.Flush()
}

// appendTags append default tags to be associated with this reporter
func (r *reporter) append(tags map[string]string) {
	for k, v := range tags {
		r.defaultTags.Store(k, v)
	}
}

// tags returns input tags if it is not nil; otherwise returns default tags
func (r *reporter) tags(tags map[string]string) map[string]string {
	mergedTags := make(map[string]string)
	r.defaultTags.Range(func(key, value interface{}) bool {
		mergedTags[key.(string)] = value.(string)
		return true
	})
	for k, v := range tags {
		mergedTags[k] = v
	}
	return mergedTags
}

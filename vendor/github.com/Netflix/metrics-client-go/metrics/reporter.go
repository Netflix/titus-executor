package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"time"
)

const (
	defaultAtlasURL = "http://localhost:8088/metrics"
	// DefaultTickDuration is the period at which the reporter outputs to Atlas by default
	defaultFlushInterval = 15 * time.Second
)

// reporter will stop sending metrics when the provided Context is done. Flush() can be called before terminating the
// context to force pending metrics to be sent.
type reporter struct {
	ctx        context.Context
	log        Logger
	atlasURL   string
	globalTags map[string]string

	// these should never be closed, or operations can panic
	counterChan chan *counter
	gauageChan  chan *gauge
	timerChan   chan *timer
	flushChan   chan chan struct{}
}

type batch struct {
	values []interface{}
	done   chan struct{}
}

// Done is used to notify callers of Flush waiting on a batch to be sent
func (b *batch) Done() {
	if b.done != nil {
		close(b.done)
	}
}

// New builds the default Reporter. It is safe to be used by multiple goroutines.
func New(ctx context.Context, log Logger, tags map[string]string) Reporter {
	return WithURL(ctx, log, defaultAtlasURL, tags)
}

// WithURL allows a custom Atlas URL. See New for more details.
func WithURL(ctx context.Context, log Logger, url string, tags map[string]string) Reporter {
	return WithURLInterval(ctx, log, url, defaultFlushInterval, tags)
}

// WithURLInterval builds a fully customized Reporter. See New for more details.
func WithURLInterval(ctx context.Context, log Logger, atlas string, flushInterval time.Duration, tags map[string]string) Reporter {
	r := &reporter{
		ctx:         ctx,
		log:         log,
		atlasURL:    atlas,
		globalTags:  tags,
		counterChan: make(chan *counter),
		gauageChan:  make(chan *gauge),
		timerChan:   make(chan *timer),
		flushChan:   make(chan chan struct{}),
	}
	batches := make(chan batch, 1)
	go r.readLoop(batches, flushInterval)
	go r.postLoop(batches)
	return r
}

// Flush blocks until pending metrics are sent. If a timeout is required, callers are responsible for wrapping this
// call.
func (r *reporter) Flush() {
	done := make(chan struct{})
	select {
	case <-r.ctx.Done():
		r.log.Println("Context is done: ignoring metrics flush")
	case r.flushChan <- done:
		<-done // wait until flush completes
	}
}

// merge with global tags for this reporter
func (r *reporter) tags(m map[string]string) map[string]string {
	mergedTags := make(map[string]string, len(r.globalTags)+len(m))
	for k, v := range r.globalTags {
		mergedTags[k] = v
	}
	for k, v := range m {
		mergedTags[k] = v
	}
	return mergedTags
}

func (r *reporter) Counter(name string, value int, tags map[string]string) {
	c := &counter{
		Timestamp: time.Now().UnixNano() / 1000000,
		Type:      "COUNTER",
		Name:      name,
		Tags:      r.tags(tags),
		Value:     uint64(value),
	}
	select {
	case <-r.ctx.Done(): // > /dev/null
	case r.counterChan <- c:
	}
}

func (r *reporter) Gauge(name string, value int, tags map[string]string) {
	g := &gauge{
		Timestamp: time.Now().UnixNano() / 1000000,
		Type:      "GAUGE",
		Name:      name,
		Tags:      r.tags(tags),
		Value:     uint64(value),
	}
	select {
	case <-r.ctx.Done(): // > /dev/null
	case r.gauageChan <- g:
	}
}

func (r *reporter) Timer(name string, value time.Duration, tags map[string]string) {
	t := &timer{
		Timestamp: time.Now().UnixNano() / 1000000,
		Type:      "TIMER",
		Name:      name,
		Tags:      r.tags(tags),
		Value:     uint64(value / 1000000),
	}
	select {
	case <-r.ctx.Done(): // > /dev/null
	case r.timerChan <- t:
	}
}

func (r *reporter) readLoop(batches chan<- batch, tickDuration time.Duration) {
	ticker := time.NewTicker(tickDuration)
	defer func() {
		// wrap in a closure because the ticker pointer can change
		ticker.Stop()
	}()

	values := make([]interface{}, 0, 15000)
	for {
		select {
		case <-r.ctx.Done():
			return
		case myCounter := <-r.counterChan:
			values = append(values, myCounter)
		case myGauge := <-r.gauageChan:
			values = append(values, myGauge)
		case myTimer := <-r.timerChan:
			values = append(values, myTimer)
		case <-ticker.C:
			values = push(r.log, batches, batch{values: values})
		case resp := <-r.flushChan:
			// Reset the ticker
			ticker.Stop()
			values = push(r.log, batches, batch{values: values, done: resp})
			ticker = time.NewTicker(tickDuration)
		}
	}
}

// push writes a batch to the channel when possible and returns a reset slice when sending was successful
func push(log Logger, batches chan<- batch, b batch) []interface{} {
	if len(b.values) == 0 {
		b.Done()
		return b.values // noop
	}
	select {
	case batches <- b:
	default:
		b.Done()
		log.Printf("Dropping %d measurements", len(b.values))
	}
	return make([]interface{}, 0, 5000)
}

func (r *reporter) postLoop(batches <-chan batch) {
	for {
		select {
		case <-r.ctx.Done():
			return
		case batch := <-batches:
			r.postMetrics(batch.values)
			batch.Done() // notify Flush callers
		}
	}
}

// postMetrics blocks and retries for at most 60s, with exponential backoff
func (r *reporter) postMetrics(batch []interface{}) {
	ctx, cancel := context.WithTimeout(r.ctx, 60*time.Second) // 60 seconds for all requests
	defer cancel()

	b, err := json.Marshal(batch)
	if err != nil {
		r.log.Printf("atlas-client-go : %s", err)
		return
	}

	for i := uint(0); i < 6; i++ {
		// 2 ** N - 1: 0, 1, 2, 4... seconds of sleep

		select {
		case <-time.After(time.Duration(1<<i-1) * time.Second):
		case <-ctx.Done():
			return
		}
		err := postToAtlas(ctx, r.log, b, r.atlasURL)

		if err == nil {
			return
		}
		r.log.Printf("atlas-client-go : %s", err)
	}
}

// postToAtlas is called for a batch of values (metrics, counters, gauges) in their JSON serialized form.
// It is meant to do a synchronous post to Atlas within time
func postToAtlas(ctx context.Context, log Logger, b []byte, atlasLoc string) error {
	// If Atlas doesn't handle disconnected clients correctly, we'll double-count metrics
	// if the request takes more than 5 seconds, because of retry
	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	req, err := http.NewRequest("POST", atlasLoc, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Add("Content-type", "application/json")
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer shouldClose(log, resp.Body)

	if statusOK(resp.StatusCode) {
		return nil
	}

	var httpResp string
	if d, err := httputil.DumpResponse(resp, true); err == nil {
		// pretty
		httpResp = string(d)
	} else {
		// fallback to an ugly and simple format
		httpResp = fmt.Sprintf("%+v", resp)
	}
	log.Printf("Metrics endpoint returned non 2xx status:\n%s", httpResp)
	return nil
}

// true for all 2xx HTTP status codes
func statusOK(code int) bool {
	return 200 <= code && code < 300
}

func shouldClose(log Logger, c io.Closer) {
	if err := c.Close(); err != nil {
		log.Printf("Error closing: %v", err)
	}
}

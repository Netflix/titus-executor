package spectator

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"go.opencensus.io/stats/view"
)

var (
	_ view.Exporter = (*Registry)(nil)
)

type Meter interface {
	MeterId() *Id
	Measure() []Measurement
}

type Config struct {
	Frequency  time.Duration     `json:"frequency"`
	Timeout    time.Duration     `json:"timeout"`
	Uri        string            `json:"uri"`
	BatchSize  int               `json:"batch_size"`
	CommonTags map[string]string `json:"common_tags"`
	Log        Logger
	IsEnabled  func() bool
}

type Registry struct {
	clock   Clock
	config  *Config
	meters  map[string]Meter
	started bool
	mutex   *sync.Mutex
	http    *HttpClient
	quit    chan struct{}
}

func NewRegistryConfiguredBy(filePath string) (*Registry, error) {
	path := filepath.Clean(filePath)
	/* #nosec G304 */
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		return nil, err
	}

	config.Timeout *= time.Second
	config.Frequency *= time.Second
	return NewRegistry(&config), nil
}

func NewRegistry(config *Config) *Registry {
	if config.IsEnabled == nil {
		config.IsEnabled = func() bool { return true }
	}
	if config.Log == nil {
		config.Log = defaultLogger()
	}

	r := &Registry{&SystemClock{}, config, map[string]Meter{}, false,
		&sync.Mutex{}, nil, make(chan struct{})}
	r.http = NewHttpClient(r, r.config.Timeout)
	return r
}

func (r *Registry) Meters() []Meter {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	meters := make([]Meter, 0, len(r.meters))
	for _, m := range r.meters {
		meters = append(meters, m)
	}
	return meters
}

func (r *Registry) Clock() Clock {
	return r.clock
}

func (r *Registry) SetLogger(logger Logger) {
	r.config.Log = logger
}

func (r *Registry) Start() error {
	if r.config == nil || r.config.Uri == "" {
		err := fmt.Sprintf("registry config has no uri. Ignoring Start request")
		r.config.Log.Infof(err)
		return fmt.Errorf(err)
	}
	if r.started {
		err := fmt.Sprintf("registry has already started. Ignoring Start request")
		r.config.Log.Infof(err)
		return fmt.Errorf(err)
	}

	r.started = true
	r.quit = make(chan struct{})
	ticker := time.NewTicker(r.config.Frequency)
	go func() {
		for {
			select {
			case <-ticker.C:
				// send measurements
				r.config.Log.Debugf("Sending measurements")
				r.publish()
			case <-r.quit:
				ticker.Stop()
				r.config.Log.Infof("Send last updates and quit")
				return
			}
		}
	}()

	return nil
}

func (r *Registry) Stop() {
	close(r.quit)
	r.started = false
	// flush metrics
	r.publish()
}

func shouldSendMeasurement(measurement Measurement) bool {
	v := measurement.value
	if math.IsNaN(v) {
		return false
	}
	isGauge := opFromTags(measurement.id.tags) == maxOp
	return isGauge || v > 0
}

func (r *Registry) Measurements() []Measurement {
	var measurements []Measurement
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for _, meter := range r.meters {
		for _, measure := range meter.Measure() {
			if shouldSendMeasurement(measure) {
				measurements = append(measurements, measure)
			}
		}
	}
	return measurements
}

func (r *Registry) sendBatch(measurements []Measurement) {
	r.config.Log.Debugf("Sending %d measurements to %s", len(measurements), r.config.Uri)
	jsonBytes, err := r.measurementsToJson(measurements)
	if err != nil {
		r.config.Log.Errorf("Unable to convert measurements to json: %v", err)
	} else {
		var status int
		status, err = r.http.PostJson(r.config.Uri, jsonBytes)
		if status != 200 || err != nil {
			r.config.Log.Errorf("Could not POST measurements: HTTP %d %v", status, err)
		}
	}
}

func (r *Registry) publish() {
	if len(r.config.Uri) == 0 {
		return
	}

	measurements := r.Measurements()
	r.config.Log.Debugf("Got %d measurements", len(measurements))
	if !r.config.IsEnabled() {
		return
	}

	for i := 0; i < len(measurements); i += r.config.BatchSize {
		end := i + r.config.BatchSize
		if end > len(measurements) {
			end = len(measurements)
		}
		r.sendBatch(measurements[i:end])
	}
}

func (r *Registry) buildStringTable(payload *[]interface{}, measurements []Measurement) map[string]int {
	var strings = make(map[string]int)
	commonTags := r.config.CommonTags
	for k, v := range commonTags {
		strings[k] = 0
		strings[v] = 0
	}

	strings["name"] = 0
	for _, measure := range measurements {
		strings[measure.id.name] = 0
		for k, v := range measure.id.tags {
			strings[k] = 0
			strings[v] = 0
		}
	}
	sortedStrings := make([]string, 0, len(strings))
	for s := range strings {
		sortedStrings = append(sortedStrings, s)
	}
	sort.Strings(sortedStrings)
	for i, s := range sortedStrings {
		strings[s] = i
	}
	*payload = append(*payload, len(strings))
	// can't append the strings in one call since we can't convert []string to []interface{}
	for _, s := range sortedStrings {
		*payload = append(*payload, s)
	}

	return strings
}

const (
	addOp = 0
	maxOp = 10
)

func opFromTags(tags map[string]string) int {
	switch tags["statistic"] {
	case "count", "totalAmount", "totalTime", "totalOfSquares", "percentile":
		return addOp
	default:
		return maxOp
	}
}

func (r *Registry) appendMeasurement(payload *[]interface{}, strings map[string]int, m Measurement) {
	op := opFromTags(m.id.tags)
	commonTags := r.config.CommonTags
	*payload = append(*payload, len(m.id.tags)+1+len(commonTags))
	for k, v := range commonTags {
		*payload = append(*payload, strings[k])
		*payload = append(*payload, strings[v])
	}
	for k, v := range m.id.tags {
		*payload = append(*payload, strings[k])
		*payload = append(*payload, strings[v])
	}
	*payload = append(*payload, strings["name"])
	*payload = append(*payload, strings[m.id.name])
	*payload = append(*payload, op)
	*payload = append(*payload, m.value)
}

func (r *Registry) measurementsToJson(measurements []Measurement) ([]byte, error) {
	var payload []interface{}
	strings := r.buildStringTable(&payload, measurements)
	for _, m := range measurements {
		r.appendMeasurement(&payload, strings, m)
	}

	return json.Marshal(payload)
}

type meterFactoryFun func() Meter

func (r *Registry) newMeter(id *Id, meterFactory meterFactoryFun) Meter {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	meter, exists := r.meters[id.mapKey()]
	if !exists {
		meter = meterFactory()
		r.meters[id.mapKey()] = meter
	}
	return meter
}

func (r *Registry) NewId(name string, tags map[string]string) *Id {
	return newId(name, tags)
}

func (r *Registry) CounterWithId(id *Id) *Counter {
	m := r.newMeter(id, func() Meter {
		return NewCounter(id)
	})

	c, ok := m.(*Counter)
	if ok {
		return c
	}

	r.config.Log.Errorf("Unable to register a counter with id=%v - a meter %v exists", id, c)

	// should throw in strict mode
	return NewCounter(id)
}

func (r *Registry) Counter(name string, tags map[string]string) *Counter {
	return r.CounterWithId(newId(name, tags))
}

func (r *Registry) TimerWithId(id *Id) *Timer {
	m := r.newMeter(id, func() Meter {
		return NewTimer(id)
	})

	t, ok := m.(*Timer)
	if ok {
		return t
	}

	r.config.Log.Errorf("Unable to register a timer with %v - a meter %v exists", id, t)

	// throw in strict mode
	return NewTimer(id)
}

func (r *Registry) Timer(name string, tags map[string]string) *Timer {
	return r.TimerWithId(newId(name, tags))
}

func (r *Registry) GaugeWithId(id *Id) *Gauge {
	m := r.newMeter(id, func() Meter {
		return NewGauge(id)
	})

	g, ok := m.(*Gauge)
	if ok {
		return g
	}

	r.config.Log.Errorf("Unable to register a gauge with id=%v - a meter %v exists", id, g)

	// throw in strict mode
	return NewGauge(id)
}

func (r *Registry) Gauge(name string, tags map[string]string) *Gauge {
	return r.GaugeWithId(newId(name, tags))
}

func (r *Registry) DistributionSummaryWithId(id *Id) *DistributionSummary {
	m := r.newMeter(id, func() Meter {
		return NewDistributionSummary(id)
	})

	d, ok := m.(*DistributionSummary)
	if ok {
		return d
	}

	r.config.Log.Errorf("Unable to register a distribution summary with id=%v - a meter %v exists", id, d)

	// throw in strict mode
	return NewDistributionSummary(id)
}

func (r *Registry) DistributionSummary(name string, tags map[string]string) *DistributionSummary {
	return r.DistributionSummaryWithId(newId(name, tags))
}

func (r *Registry) opencensusDistributionDataWithId(id *Id) *opencensusDistributionData {
	m := r.newMeter(id, func() Meter {
		return newOpencensusDistributionData(id)
	})

	d, ok := m.(*opencensusDistributionData)
	if ok {
		return d
	}

	r.config.Log.Errorf("Unable to register a gauge with id=%v - an opencensusDistributionData meter %v exists", id, d)

	// throw in strict mode
	return newOpencensusDistributionData(id)
}

func (r *Registry) ExportView(vd *view.Data) {
	for _, row := range vd.Rows {
		tags := make(map[string]string, len(row.Tags))
		for idx := range row.Tags {
			tags[row.Tags[idx].Key.Name()] = row.Tags[idx].Value
		}

		id := newId(vd.View.Name, tags)
		switch v := row.Data.(type) {
		case *view.DistributionData:
			r.opencensusDistributionDataWithId(id).update(v)
		case *view.CountData:
			r.CounterWithId(id).Add(v.Value)
		case *view.SumData:
			r.CounterWithId(id).AddFloat(v.Value)
		case *view.LastValueData:
			r.GaugeWithId(id).Set(v.Value)
		}
	}
}

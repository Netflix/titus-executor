package properties

import (
	"sync/atomic"

	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Netflix/quitelite-client-go/properties/circuit"
	log "github.com/sirupsen/logrus"
)

type state int

var globalShortCircuit = circuit.NewCircuit()

// ShortCircuit makes it so that the service does not rely on quitelite to startup
func ShortCircuit() {
	globalShortCircuit.ShortCircuitForever()
}

const (
	unconnected state = iota
	connected
)

type payload struct {
	Value        *interface{} `json:"value"`
	DefaultValue bool         `json:"defaultValue"`
}

// DynamicProperty holds the channel with dynamic property updates. The channel will immediately return a value.  You
// must call Stop on the DynamicProperty because automatic GC wont collect it, otherwise it will leak.
type DynamicProperty struct {
	log                 *log.Entry
	ctx                 context.Context
	cancel              context.CancelFunc
	C                   <-chan *DynamicPropertyValue
	c                   chan *DynamicPropertyValue
	value               atomic.Value
	defaultValue        *DynamicPropertyValue
	dynamicPropertyName string
	state               state
	condition           *sync.Cond
	httpClient          http.Client
	currentJSONDecoder  *json.Decoder
	currentResponse     io.ReadCloser
	host                string
	retries             int
	circuit             *circuit.Circuit
}

// NewDynamicProperty returns an initialized instance of DynamicProperty for the given dynamicPropertyName. The
// defaultValue will be immediately returned. If the value is set, and then unset in Prana, it'll revert
// to the defaultValue
func NewDynamicProperty(parentCtx context.Context, dynamicPropertyName string, defaultValue interface{}, host string, circuit *circuit.Circuit) *DynamicProperty {
	if host == "" {
		host = "localhost:3002"
	}
	c := make(chan *DynamicPropertyValue, 1)
	ctx, cancel := context.WithCancel(parentCtx)
	if circuit == nil {
		circuit = globalShortCircuit
	}
	dp := &DynamicProperty{
		log:                 log.WithField("dynamicPropertyName", dynamicPropertyName).WithField("defaultValue", defaultValue),
		ctx:                 ctx,
		cancel:              cancel,
		C:                   c,
		c:                   c,
		defaultValue:        newDynamicPropertyValue(castType(defaultValue)),
		condition:           sync.NewCond(&sync.Mutex{}),
		httpClient:          http.Client{},
		dynamicPropertyName: dynamicPropertyName,
		host:                host,
		circuit:             circuit,
	}
	dp.value.Store(dp.defaultValue)
	fence := make(chan struct{})
	go dp.watchDynamicProperty(fence)
	initializedChan := make(chan struct{})
	go func() {
		dp.condition.L.Lock()
		defer dp.condition.L.Unlock()
		dp.condition.Wait()
		close(initializedChan)
	}()

	close(fence)

	select {
	case <-dp.circuit.ShortCircuitChan():
		dp.log.Info("Short circuit activated")
		dp.condition.Broadcast()
	case <-time.After(5 * time.Second):
		dp.log.Warning("Took more than 5 seconds to initialized, falling back to default value")
		dp.log.Warning("Going to short-circuit, as it does not looke like quitelite is alive. Short-circuit will last 1-minute.")
		dp.circuit.ShortCircuitForDuration(1 * time.Minute)
		dp.condition.Broadcast()
	case <-initializedChan:
	}
	go dp.feedLoop()

	return dp
}

func (dp *DynamicProperty) ticker() <-chan struct{} {
	ticker := make(chan struct{})
	go func() {
		for {
			dp.condition.L.Lock()
			dp.condition.Wait()
			dp.condition.L.Unlock()
			dp.log.Debug("Waking up")
			select {
			case <-dp.ctx.Done():
				return
			default:
				ticker <- struct{}{}
			}
		}
	}()
	return ticker
}

func (dp *DynamicProperty) feedLoop() {
	lastValueSeen := dp.Read()
	ticker := dp.ticker()

	dp.c <- lastValueSeen
	for {
		select {
		case <-dp.ctx.Done():
			return
		case <-ticker:
			nextValue := dp.Read()
			dp.log.WithField("nextValue", nextValue).WithField("lastValueSeen", lastValueSeen).Debug("Tick")
			if !nextValue.Equal(*lastValueSeen) {
				select {
				case <-dp.ctx.Done():
					return
				case <-ticker:
				case dp.c <- nextValue:
					lastValueSeen = nextValue
				}
			}
		}
	}
}

// Stop doesn't stop running the Prana poller in the background, but it stops updates on the channel
func (dp *DynamicProperty) Stop() {
	dp.cancel()
}

// Read fetches the last value pushed to the channel
func (dp *DynamicProperty) Read() *DynamicPropertyValue {
	return dp.value.Load().(*DynamicPropertyValue)
}

func (dp *DynamicProperty) watchDynamicProperty(fence chan struct{}) {
	defer dp.cancel()
	<-fence
	for {
		switch dp.state {
		case connected:
			dp.state = dp.handleConnected()
		case unconnected:
			dp.state = dp.handleUnconnected()
		}
		if dp.ctx.Err() != nil {
			dp.log.Debug("Watching discontinued")
			return
		}
	}
}

func maybeSleepBeforeConnect(retries int) {
	switch retries {
	case 0:
	case 1:
		time.Sleep(1 * time.Second)
	case 2:
		time.Sleep(2 * time.Second)
	case 3:
		time.Sleep(4 * time.Second)
	case 4:
		time.Sleep(8 * time.Second)
	default:
		time.Sleep(10 * time.Second)
	}
}
func (dp *DynamicProperty) tryConnect() (*http.Response, error) {
	dp.log.WithField("retries", dp.retries).Debug("Attempting to connect to quitelite")
	maybeSleepBeforeConnect(dp.retries)
	dp.retries = dp.retries + 1

	v := url.Values{}
	url := url.URL{
		Host:     dp.host,
		Scheme:   "http",
		RawQuery: v.Encode(),
		Path:     fmt.Sprintf("/properties/streaming/%s", dp.dynamicPropertyName),
	}

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		dp.log.Fatal("Unable to create http request to quitelite")
	}
	req.Header.Add("Accept", "application/json")

	/* This shouldn't take too long to do */
	resp, err := dp.httpClient.Do(req.WithContext(dp.ctx))

	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("Unknown status received from quitelite: %d", resp.StatusCode)
	}

	dp.log.Debug("Connected successfully to quitelite")
	dp.retries = 0

	return resp, nil
}

func (dp *DynamicProperty) handleConnected() state {
	var newPayload payload
	dp.log.Debug("Waiting on new value")
	err := dp.currentJSONDecoder.Decode(&newPayload)
	dp.log.Debug("Received new value from quitelite")
	if err != nil {
		// Should we revert to the default value? Probably not
		dp.log.Warn("Lost connection to quitelite: ", err)
		shouldClose(dp.currentResponse)
		return unconnected
	}

	if !newPayload.DefaultValue && newPayload.Value != nil {
		dp.value.Store(newDynamicPropertyValue(newPayload.Value))
	} else {
		dp.value.Store(dp.defaultValue)
	}

	dp.condition.Broadcast()
	return connected
}

func (dp *DynamicProperty) handleUnconnected() state {
	resp, err := dp.tryConnect()
	if err != nil {
		if !dp.circuit.ShortCircuited() {
			dp.log.Warning("Unable to connect to quitelite: ", err)
		}
		return unconnected
	}
	dp.currentResponse = resp.Body
	dp.currentJSONDecoder = json.NewDecoder(resp.Body)
	return connected
}

func shouldClose(closer io.Closer) {
	if err := closer.Close(); err != nil {
		log.Warning("Unable to close io closer because: ", err)
	}
}

// nolint: gocyclo
func castType(val interface{}) interface{} {
	switch v := (val).(type) {
	case bool:
		return val
	case float64:
		return val
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int8:
		return float64(v)
	case int16:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case uint:
		return float64(v)
	case uint8:
		return float64(v)
	case uint16:
		return float64(v)
	case uint32:
		return float64(v)
	case uint64:
		return float64(v)
	case string:
		return val
	case time.Duration:
		return v.String()
	default:
		panic("Invalid default value type")
	}
}

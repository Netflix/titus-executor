package client

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	"io"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/launchguard/core"
	"github.com/pborman/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	// MaxLaunchTime is the Maximum time a launch event will stay active before we decide launchguard is going to be ignored
	MaxLaunchTime = 10 * time.Minute
	// RefreshWindow is how often launch events should be renewed, or will be considered dead by the server
	RefreshWindow = time.Second
	defaultKey    = "default"
)

// LaunchGuardClient coordinates the starting and shutting down of containers
type LaunchGuardClient struct {
	httpClient http.Client
	url        *url.URL
	m          metrics.Reporter
}

var (
	_ core.LaunchEvent  = (*ClientLaunchEvent)(nil)
	_ core.CleanUpEvent = (*ClientCleanupEvent)(nil)
)

// ClientLaunchEvent is used to synchronize launching containers
type ClientLaunchEvent struct { // nolint: golint
	ch chan struct{}
}

// Launch returns a channel which will be closed once you're allowed to launch
func (cle *ClientLaunchEvent) Launch() <-chan struct{} {
	return cle.ch
}

// ClientCleanupEvent should be used when tearing a container down
type ClientCleanupEvent struct { // nolint: golint
	once   sync.Once
	key    string
	id     string
	lgc    *LaunchGuardClient
	cancel context.CancelFunc
	ch     chan struct{}
}

// Done is used to indicate that the event has been cleaned up, and the launch guard can move on. It is idempotent.
func (cce *ClientCleanupEvent) Done() {
	cce.once.Do(func() {
		close(cce.ch)
	})
}
func (cce *ClientCleanupEvent) run(ctx context.Context) {
	ticker := time.NewTicker(RefreshWindow)
	defer ticker.Stop()
	defer cce.cancel()
	for {
		select {
		case <-ctx.Done():
			// We timed out, bail
			return
		case <-cce.ch:
			if err := cce.delete(ctx); err != nil {
				log.Warning("Deletion failed: ", err)
			}
			return
		case <-ticker.C:
			if err := cce.heartbeat(ctx); err != nil {
				log.Warning("Heartbeat failed, assuming cleanup event is done: ", err)
				return
			}
		}
	}
}

func (cce *ClientCleanupEvent) heartbeat(ctx context.Context) error {
	url := *cce.lgc.url

	url.Path = fmt.Sprintf("/launchguard/%s/cleanupevent/%s/heartbeat", cce.key, cce.id)
	request, err := http.NewRequest("POST", url.String(), nil)
	if err != nil {
		panic("Unable to create request")
	}
	resp, err := cce.lgc.httpClient.Do(request.WithContext(ctx))

	if err != nil {
		return fmt.Errorf("Heartbeat failed: %v", err)
	}

	shouldClose(resp.Body)
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}

	return fmt.Errorf("Heartbeat failed, status: %s", resp.Status)
}

func (cce *ClientCleanupEvent) delete(parentCtx context.Context) error {
	// No reason to let this ever go on more than a second
	ctx, cancel := context.WithTimeout(parentCtx, time.Second)
	defer cancel()

	url := *cce.lgc.url

	url.Path = fmt.Sprintf("/launchguard/%s/cleanupevent/%s", cce.key, cce.id)
	request, err := http.NewRequest("DELETE", url.String(), nil)
	if err != nil {
		panic("Unable to create request")
	}
	resp, err := cce.lgc.httpClient.Do(request.WithContext(ctx))

	if err != nil {
		return fmt.Errorf("Deletion failed: %v", err)
	}

	shouldClose(resp.Body)
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	return fmt.Errorf("Deletion failed, status: %s", resp.Status)
}

// NewLaunchGuardClient instantiates a new client for the launchguard server.
func NewLaunchGuardClient(m metrics.Reporter, baseuri string) (*LaunchGuardClient, error) {
	client := http.Client{
		Timeout: 0,
	}
	url, err := url.Parse(baseuri)
	if err != nil {
		return nil, err
	}
	return &LaunchGuardClient{
		httpClient: client,
		url:        url,
		m:          m,
	}, nil
}

// NewRealCleanUpEvent must be used to instantiate new real cleanup events
func (lgc *LaunchGuardClient) NewRealCleanUpEvent(parentCtx context.Context, key string) core.CleanUpEvent {
	if key == "" {
		key = defaultKey
	}
	ctx, cancel := context.WithTimeout(parentCtx, MaxLaunchTime)
	ce := &ClientCleanupEvent{
		key:    key,
		id:     uuid.New(),
		lgc:    lgc,
		cancel: cancel,
		ch:     make(chan struct{}),
	}

	url := *lgc.url

	url.Path = fmt.Sprintf("/launchguard/%s/cleanupevent/%s", key, ce.id)
	request, err := http.NewRequest("PUT", url.String(), nil)
	if err != nil {
		panic("Unable to create request")
	}
	resp, err := lgc.httpClient.Do(request.WithContext(ctx))
	if err == nil {
		shouldClose(resp.Body)
		if resp.StatusCode == http.StatusCreated {
			go ce.run(ctx)
			return ce
		}
	}
	if resp != nil {
		log.WithField("statusCode", resp.StatusCode).Warning("Unable to create cleanup event: ", err)
	} else {
		log.Warning("Unable to create cleanup event: ", err)
	}
	cancel()
	return ce
}

// NewLaunchEvent returns a launch event. This launch event creation may block for up to MaxLaunchTime,
// but you must look at the channel in order to get actual clearance to launch
func (lgc *LaunchGuardClient) NewLaunchEvent(parentCtx context.Context, key string) core.LaunchEvent {
	if key == "" {
		key = defaultKey
	}

	var url url.URL

	ctx, cancel := context.WithTimeout(parentCtx, MaxLaunchTime)
	launchEvent := &ClientLaunchEvent{make(chan struct{})}

	url = *lgc.url
	url.Path = fmt.Sprintf("/launchguard/%s/launchevent", key)
	log.Info(url)
	request, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		panic("Unable to create request")
	}
	resp, err := lgc.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		log.Error("Error creating client-side launch event: ", err)
		close(launchEvent.ch)
		cancel()
		return launchEvent
	}
	go func() {
		defer cancel()
		defer close(launchEvent.ch)

		buf, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error("Error reading client-side launch event info: ", err)
		}
		shouldClose(resp.Body)
		log.Debug("Launch event finished: ", string(buf))
	}()
	return launchEvent
}

func shouldClose(closeable io.Closer) {
	if err := closeable.Close(); err != nil {
		log.Errorf("Unable to close %v because: %v", closeable, err)
	}
}

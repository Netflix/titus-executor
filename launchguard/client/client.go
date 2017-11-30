package client

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/launchguard/core"
	"github.com/pborman/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	MaxLaunchTime = 10 * time.Minute
	RefreshWindow = time.Second
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

type ClientLaunchEvent struct {
	ch chan struct{}
}

func (cle *ClientLaunchEvent) Launch() <-chan struct{} {
	return cle.ch
}

type ClientCleanupEvent struct {
	once   sync.Once
	key    string
	id     string
	lgc    *LaunchGuardClient
	cancel context.CancelFunc
	ch     chan struct{}
}

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
	var url url.URL
	url = *cce.lgc.url

	url.Path = fmt.Sprintf("/launchguard/%s/cleanupevent/%s/heartbeat", cce.key, cce.id)
	request, err := http.NewRequest("POST", url.String(), nil)
	if err != nil {
		panic("Unable to create request")
	}
	resp, err := cce.lgc.httpClient.Do(request.WithContext(ctx))

	if err != nil {
		return fmt.Errorf("Heartbeat failed: %v", err)
	}

	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}

	return fmt.Errorf("Heartbeat failed, status: %s", resp.Status)
}

func (cce *ClientCleanupEvent) delete(parentCtx context.Context) error {
	// No reason to let this ever go on more than a second
	ctx, cancel := context.WithTimeout(parentCtx, time.Second)
	defer cancel()

	var url url.URL
	url = *cce.lgc.url

	url.Path = fmt.Sprintf("/launchguard/%s/cleanupevent/%s", cce.key, cce.id)
	request, err := http.NewRequest("DELETE", url.String(), nil)
	if err != nil {
		panic("Unable to create request")
	}
	resp, err := cce.lgc.httpClient.Do(request.WithContext(ctx))

	if err != nil {
		return fmt.Errorf("Deletion failed: %v", err)
	}

	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	return fmt.Errorf("Deletion failed, status: %s", resp.Status)
}

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
	ctx, cancel := context.WithTimeout(parentCtx, MaxLaunchTime)
	ce := &ClientCleanupEvent{
		key:    key,
		id:     uuid.New(),
		lgc:    lgc,
		cancel: cancel,
		ch:     make(chan struct{}),
	}

	var url url.URL
	url = *lgc.url

	url.Path = fmt.Sprintf("/launchguard/%s/cleanupevent/%s", key, ce.id)
	request, err := http.NewRequest("PUT", url.String(), nil)
	if err != nil {
		panic("Unable to create request")
	}
	resp, err := lgc.httpClient.Do(request.WithContext(ctx))
	if err == nil {
		_ = resp.Body.Close()
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

// Will block
func (lgc *LaunchGuardClient) NewLaunchEvent(parentCtx context.Context, key string) core.LaunchEvent {
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
		return launchEvent
	}
	go func() {
		defer cancel()
		defer close(launchEvent.ch)

		buf, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error("Error reading client-side launch event info: ", err)
		}
		_ = resp.Body.Close()
		log.Debug("Launch event finished: ", string(buf))
	}()
	return launchEvent
}

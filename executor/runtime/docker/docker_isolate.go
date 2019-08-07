package docker

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	titusIsolateHost = "localhost:7500"
	retryTime        = 100 * time.Millisecond
)

func waitForTitusIsolate(parentCtx context.Context, taskID string, timeout time.Duration) {
	waitForTitusIsolateWithHost(parentCtx, taskID, titusIsolateHost, timeout)
}

func waitForTitusIsolateWithHost(parentCtx context.Context, taskID, host string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	ticker := time.NewTicker(retryTime)

	firstTry := make(chan struct{}, 1)
	firstTry <- struct{}{}
	for {
		select {
		case <-ctx.Done():
			logrus.WithError(ctx.Err()).Warn("Context completed prior to getting a successful result from titus isolate")
			return false

		case <-ticker.C:
			if workloadIsolated(ctx, taskID, host) {
				return true
			}
		case <-firstTry:
			if workloadIsolated(ctx, taskID, host) {
				return true
			}
		}
	}
}

// workloadIsolated waits for titus-isolate to return from our request to see if the workload has been isolated.
// we want to wait for titus-isolate because some workloads look at the CPUs at container start time.
func workloadIsolated(ctx context.Context, taskID, host string) bool {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	requestURL := &url.URL{
		Scheme: "http",
		Host:   host,
		Path:   fmt.Sprintf("/isolate/%s", taskID),
	}

	rq, err := http.NewRequest("GET", requestURL.String(), http.NoBody)
	if err != nil {
		logrus.WithError(err).Warn("Could not form HTTP Request to Isolate")
		return false
	}
	rq = rq.WithContext(ctx)
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		Timeout: time.Second,
	}
	resp, err := client.Do(rq)
	// Check if context timed out
	if err != nil {
		logrus.WithError(err).Warn("Error calling titus isolate")
		return false
	}

	defer shouldClose(resp.Body)

	if resp.StatusCode == 200 {
		return true
	}

	logrus.WithFields(map[string]interface{}{
		"statusCode": resp.StatusCode,
		"status":     resp.Status,
	}).Warn("Titus Isolate did not return code 200")
	return false
}

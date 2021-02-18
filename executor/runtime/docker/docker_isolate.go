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
	tries := 0

	firstTry := make(chan struct{}, 1)
	firstTry <- struct{}{}
	for {
		select {
		case <-ticker.C:
			// select is pseudo-random, so simply selecting for ctx.Done() is not
			// guaranteed to make sure we `select` for that case first, just because
			// it comes first in our case statement. Therefore we check it explicitly
			// right before we do any other actions based on the ticket signal
			if ctx.Err() != nil {
				logrus.WithError(ctx.Err()).WithField("tries", tries).Warn("Context completed prior to getting a successful result from titus isolate")
				return false
			}
			tries++
			if workloadIsolated(ctx, taskID, host) {
				logrus.WithField("tries", tries).Info("Titus Isolate returned success")
				return true
			}
		case <-firstTry:
			tries++
			if workloadIsolated(ctx, taskID, host) {
				logrus.WithField("tries", tries).Info("Titus Isolate returned success")
				return true
			}
		}
	}
}

// workloadIsolated waits for titus-isolate to return from our request to see if the workload has been isolated.
// we want to wait for titus-isolate because some workloads look at the CPUs at container start time.
// Note that this is non-blocking on the titus-isolate side.
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

	if resp.StatusCode == 404 {
		// isolate returns 404 when the isolation operation hasn't completed yet
		return false
	}

	// Only log unexpected status codes

	logrus.WithFields(map[string]interface{}{
		"statusCode": resp.StatusCode,
		"status":     resp.Status,
	}).Warn("Titus Isolate did not return code 200")
	return false
}

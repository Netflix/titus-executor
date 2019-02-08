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
)

func waitForTitusIsolate(parentCtx context.Context, taskID string, timeout time.Duration) {
	waitForTitusIsolateWithHost(parentCtx, taskID, titusIsolateHost, timeout)
}

func waitForTitusIsolateWithHost(parentCtx context.Context, taskID, host string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	requestURL := &url.URL{
		Scheme: "http",
		Host:   host,
		Path:   fmt.Sprintf("/isolate/%s", taskID),
	}

	rq, err := http.NewRequest("GET", requestURL.String(), http.NoBody)
	if err != nil {
		logrus.WithError(err).Warn("Could not form HTTP Request to Isolate")
		return
	}
	rq = rq.WithContext(ctx)
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
	resp, err := client.Do(rq)
	// Check if context timed out
	if err != nil {
		logrus.WithError(err).Warn("Error calling titus isolate")
		return
	}

	defer shouldClose(resp.Body)

	if resp.StatusCode == 200 {
		return
	}

	logrus.WithFields(map[string]interface{}{
		"statusCode": resp.StatusCode,
		"status":     resp.Status,
	}).Warn("Titus Isolate did not return code 200")
}

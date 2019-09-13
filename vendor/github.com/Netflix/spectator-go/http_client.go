package spectator

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type HttpClient struct {
	registry *Registry
	timeout  time.Duration
}

func NewHttpClient(registry *Registry, timeout time.Duration) *HttpClient {
	return &HttpClient{registry, timeout}
}

func userFriendlyErr(errStr string) string {
	if strings.Contains(errStr, "connection refused") {
		return "ConnectException"
	}

	return "HttpErr"
}

func (h *HttpClient) createPayloadRequest(uri string, jsonBytes []byte) (*http.Request, error) {
	const JsonType = "application/json"
	const CompressThreshold = 512
	compressed := len(jsonBytes) > CompressThreshold
	var payloadBuffer *bytes.Buffer
	if compressed {
		payloadBuffer = &bytes.Buffer{}
		g := gzip.NewWriter(payloadBuffer)
		if _, err := g.Write(jsonBytes); err != nil {
			return nil, errors.Wrap(err, "Unable to compress json payload")
		}
		if err := g.Close(); err != nil {
			return nil, errors.Wrap(err, "Unable to close gzip stream")
		}
	} else {
		payloadBuffer = bytes.NewBuffer(jsonBytes)
	}

	req, err := http.NewRequest("POST", uri, payloadBuffer)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "spectator-go")
	req.Header.Set("Accept", JsonType)
	req.Header.Set("Content-Type", JsonType)
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}
	return req, nil
}

func (h *HttpClient) PostJson(uri string, jsonBytes []byte) (statusCode int, err error) {
	statusCode = 400
	log := h.registry.config.Log
	var req *http.Request
	req, err = h.createPayloadRequest(uri, jsonBytes)
	if err != nil {
		panic(err)
	}
	client := http.Client{}
	client.Timeout = h.timeout

	tags := map[string]string{
		"client": "spectator-go",
		"method": "POST",
		"mode":   "http-client",
	}

	clock := h.registry.clock
	start := clock.Now()
	log.Debugf("posting data to %s, payload %d bytes", uri, len(jsonBytes))
	resp, err := client.Do(req)
	if err != nil {
		if urlerr, ok := err.(*url.Error); ok {
			if urlerr.Timeout() {
				tags["status"] = "timeout"
			} else if urlerr.Temporary() {
				tags["status"] = "temporary"
			} else {
				tags["status"] = userFriendlyErr(urlerr.Err.Error())
			}
		} else {
			tags["status"] = err.Error()
		}
		tags["statusCode"] = tags["status"]
		log.Errorf("Unable to POST to %s: %v", uri, err)
	} else {
		defer func() {
			if err = resp.Body.Close(); err != nil {
				log.Errorf("Unable to close body: %v", err)
			}
		}()
		statusCode = resp.StatusCode
		tags["statusCode"] = strconv.Itoa(resp.StatusCode)
		tags["status"] = fmt.Sprintf("%dxx", resp.StatusCode/100)
		var body []byte
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("Unable to read response body: %v", err)
			return
		}
		log.Debugf("response HTTP %d: %s", resp.StatusCode, body)
	}
	elapsed := clock.Now().Sub(start)
	h.registry.Timer("http.req.complete", tags).Record(elapsed)
	return
}

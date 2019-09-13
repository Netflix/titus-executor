[![Build Status](https://travis-ci.org/Netflix/spectator-go.svg?branch=master)](https://travis-ci.org/Netflix/spectator-go) 
# Spectator-go

> :warning: Experimental
 
Simple library for instrumenting code to record dimensional time series.

## Description

This implements a basic [Spectator](https://github.com/Netflix/spectator)
library for instrumenting golang applications, sending metrics to an Atlas
aggregator service.

## Instrumenting Code

```go
package main

import (
	"github.com/Netflix/spectator-go"
	"strconv"
	"time"
)

type Server struct {
	registry       *spectator.Registry
	requestCountId *spectator.Id
	requestLatency *spectator.Timer
	responseSizes  *spectator.DistributionSummary
}

type Request struct {
	country string
}

type Response struct {
	status int
	size   int64
}

func (s *Server) Handle(request *Request) (res *Response) {
	clock := s.registry.Clock()
	start := clock.Now()

	// initialize res
	res = &Response{200, 64}

	// Update the counter id with dimensions based on the request. The
	// counter will then be looked up in the registry which should be
	// fairly cheap, such as lookup of id object in a map
	// However, it is more expensive than having a local variable set
	// to the counter.
	cntId := s.requestCountId.WithTag("country", request.country).WithTag("status", strconv.Itoa(res.status))
	s.registry.CounterWithId(cntId).Increment()

	// ...
	s.requestLatency.Record(clock.Now().Sub(start))
	s.responseSizes.Record(res.size)
	return
}

func newServer(registry *spectator.Registry) *Server {
	return &Server{
		registry,
		registry.NewId("server.requestCount", nil),
		registry.Timer("server.requestLatency", nil),
		registry.DistributionSummary("server.responseSizes", nil),
	}
}

func getNextRequest() *Request {
	// ...
	return &Request{"US"}
}

func main() {
	commonTags := map[string]string{"nf.app": "example", "nf.region": "us-west-1"}
	config := &spectator.Config{Frequency: 5 * time.Second, Timeout: 1 * time.Second,
		Uri: "http://example.org/api/v1/publish", CommonTags: commonTags}
	registry := spectator.NewRegistry(config)

	// optionally set custom logger (needs to implement Debugf, Infof, Errorf)
	// registry.SetLogger(logger)
	registry.Start()
	defer registry.Stop()

	// collect memory and file descriptor metrics
	spectator.CollectRuntimeMetrics(registry)

	server := newServer(registry)

	for i := 1; i < 3; i++ {
		// get a request
		req := getNextRequest()
		server.Handle(req)
	}
}

```



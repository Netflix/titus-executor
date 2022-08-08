package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockDynamicConfigServer struct {
	sync.Mutex
	configsByName map[string]string
	srv           *http.Server
	url           string
}

func (s *mockDynamicConfigServer) start(wg *sync.WaitGroup, t *testing.T) {
	s.srv = &http.Server{Addr: "localhost:0"}

	http.HandleFunc("/properties", func(w http.ResponseWriter, r *http.Request) {
		s.Lock()
		defer s.Unlock()
		bytes, err := json.Marshal(s.configsByName)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			_, _ = w.Write(bytes)
		}
	})

	listener, err := net.Listen("tcp", "localhost:0")
	assert.NoError(t, err)

	s.url = fmt.Sprintf("http://localhost:%d/properties", listener.Addr().(*net.TCPAddr).Port)

	go func() {
		defer wg.Done()

		_ = s.srv.Serve(listener)
	}()
}

func TestDynamicConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// Start a mock dynamic config provider
	wg := &sync.WaitGroup{}
	wg.Add(1)

	s := mockDynamicConfigServer{
		configsByName: map[string]string{
			"TEST_INT_CONFIG":  "24",
			"TEST_BOOL_CONFIG": "true",
		},
	}
	s.start(wg, t)

	dynamicConfig := NewDynamicConfig()

	// Before starting fetching configs, the value should be default value
	assert.Equal(t, 123, dynamicConfig.GetInt(ctx, "TEST_INT_CONFIG", 123))
	assert.Equal(t, false, dynamicConfig.GetBool(ctx, "TEST_BOOL_CONFIG", false))

	interval := time.Second
	dynamicConfig.Start(ctx, interval, s.url)

	done := make(chan bool)
	var actualIntValue int
	// Keep checking the config value until it changes.
	go func() {
		for {
			actualIntValue = dynamicConfig.GetInt(ctx, "TEST_INT_CONFIG", 123)
			if actualIntValue != 123 {
				done <- true
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	select {
	case <-done:
		assert.Equal(t, 24, actualIntValue)
		assert.Equal(t, true, dynamicConfig.GetBool(ctx, "TEST_BOOL_CONFIG", false))
	case <-time.After(2 * interval):
		assert.Fail(t, "Failed to fetch latest value after 2 intervals")
	}

	cancel()
	_ = s.srv.Shutdown(ctx)

	wg.Wait()
}

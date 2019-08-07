package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTitusIsolateTimeout(t *testing.T) {
	t.Parallel()
	handler := func(w http.ResponseWriter, r *http.Request) {
		// This function will not return quickly.
		t := time.NewTimer(30 * time.Second)
		defer t.Stop()
		select {
		case <-t.C:
		case <-r.Context().Done():
		}
		w.WriteHeader(200)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	now := time.Now()
	assert.False(t, waitForTitusIsolateWithHost(ctx, "timeout", server.Listener.Addr().String(), 1*time.Second))
	assert.True(t, time.Since(now) < 15*time.Second)
}

func TestTitusIsolateTimeoutThenSuccess(t *testing.T) {
	t.Parallel()

	var tryCount uint64
	handler := func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddUint64(&tryCount, 1) > 3 {
			w.WriteHeader(200)
			return
		}
		// This function will not return quickly.
		t := time.NewTimer(30 * time.Second)
		defer t.Stop()
		select {
		case <-t.C:
		case <-r.Context().Done():
		}
		w.WriteHeader(200)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	assert.True(t, waitForTitusIsolateWithHost(ctx, "foo", server.Listener.Addr().String(), 10*time.Second))
}

func TestTitusIsolateSuccess(t *testing.T) {
	t.Parallel()
	handler := func(w http.ResponseWriter, r *http.Request) {
		// This function will return quickly.
		w.WriteHeader(200)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	now := time.Now()
	assert.True(t, waitForTitusIsolateWithHost(ctx, "foo", server.Listener.Addr().String(), 1*time.Second))
	assert.True(t, time.Since(now) < 5*time.Second)
}

func TestTitusIsolate404(t *testing.T) {
	t.Parallel()
	handler := func(w http.ResponseWriter, r *http.Request) {
		// This function will return quickly.
		w.WriteHeader(404)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	now := time.Now()
	assert.False(t, waitForTitusIsolateWithHost(ctx, "foo", server.Listener.Addr().String(), 1*time.Second))
	assert.True(t, time.Since(now) < 5*time.Second)
}

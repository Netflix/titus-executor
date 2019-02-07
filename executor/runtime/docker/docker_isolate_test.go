package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	waitForTitusIsolateWithHost(ctx, "foo", server.Listener.Addr().String(), 1*time.Second)
	assert.True(t, time.Since(now) < 15*time.Second)
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
	waitForTitusIsolateWithHost(ctx, "foo", server.Listener.Addr().String(), 1*time.Second)
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
	waitForTitusIsolateWithHost(ctx, "foo", server.Listener.Addr().String(), 1*time.Second)
	assert.True(t, time.Since(now) < 5*time.Second)
}

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPing(t *testing.T) {
	r := newMux()
	server := httptest.NewServer(r)
	defer server.Close()

	_, err := http.Get(server.URL + "/ping")
	if err != nil {
		t.Fatal("Unexpected error")
	}
}

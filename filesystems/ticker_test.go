package filesystems

import (
	"context"
	"testing"
	"time"
)

func TestTicker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	now := time.Now()

	c := newTicker(ctx, time.Millisecond*100)
	// Ensure we get at least one tick
	<-c
	cancel()
	// This should terminate
	for range c {
	}

	if time.Since(now) > time.Second {
		t.Fatal("Shutdown took too long")
	}
}

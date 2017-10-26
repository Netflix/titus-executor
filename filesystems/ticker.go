package filesystems

import (
	"context"
	"time"
)

func newTicker(ctx context.Context, d time.Duration) <-chan time.Time {
	c := make(chan time.Time)
	t := time.NewTicker(d)
	go tickerLoop(ctx, c, t)
	return c
}

func tickerLoop(parentCtx context.Context, retChan chan time.Time, ticker *time.Ticker) {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	defer ticker.Stop()
	defer close(retChan)

	// Run to completion
	for {
		select {
		// If there's no current tick in flight, and context is canceled, shutdown
		case <-ctx.Done():
			return
		// We got a tick, let's try to forward it
		case forwardedTime := <-ticker.C:
			select {
			// If the ticker channel is blocked and we get a done, shutdown
			case <-ctx.Done():
				return
				// Try to forward the signal
			case retChan <- forwardedTime:
			}
		}
	}
}

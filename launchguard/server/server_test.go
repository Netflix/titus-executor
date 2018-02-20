package server

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/launchguard/client"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func ensureChannelNotClosed(t *testing.T, ch <-chan struct{}) {
	select {
	case <-ch:
		panic("Channel closed")
	default:
	}
}

func TestBasicOrdering(t *testing.T) {
	server := httptest.NewServer(NewLaunchGuardServer(metrics.Discard))

	c, err := client.NewLaunchGuardClient(metrics.Discard, server.URL)
	assert.NoError(t, err)
	ce1 := c.NewRealCleanUpEvent(context.TODO(), "test")
	logrus.Debug("a")

	le1 := c.NewLaunchEvent(context.TODO(), "test")
	logrus.Debug("b")

	le2 := c.NewLaunchEvent(context.TODO(), "test")
	logrus.Debug("c")

	ce2 := c.NewRealCleanUpEvent(context.TODO(), "test")
	logrus.Debug("d")

	ce3 := c.NewRealCleanUpEvent(context.TODO(), "test")
	le3 := c.NewLaunchEvent(context.TODO(), "test")
	le4 := c.NewLaunchEvent(context.TODO(), "test")
	ce5 := c.NewRealCleanUpEvent(context.TODO(), "test")
	le5 := c.NewLaunchEvent(context.TODO(), "test")
	ce6 := c.NewRealCleanUpEvent(context.TODO(), "test")
	ce7 := c.NewRealCleanUpEvent(context.TODO(), "test")
	ce8 := c.NewRealCleanUpEvent(context.TODO(), "test")
	ce9 := c.NewRealCleanUpEvent(context.TODO(), "test")

	ensureChannelNotClosed(t, le1.Launch())
	ensureChannelNotClosed(t, le2.Launch())
	ce1.Done()
	logrus.Debug("1")
	<-le1.Launch()
	logrus.Debug("2")

	<-le2.Launch()
	logrus.Debug("3")

	ensureChannelNotClosed(t, le3.Launch())
	ensureChannelNotClosed(t, le4.Launch())
	ce2.Done()
	logrus.Debug("4")

	ce3.Done()
	<-le3.Launch()
	<-le4.Launch()

	ensureChannelNotClosed(t, le5.Launch())
	ce5.Done()
	<-le5.Launch()
	ce6.Done()
	ce7.Done()
	ce8.Done()
	ce9.Done()

}

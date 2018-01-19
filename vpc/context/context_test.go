package context

import (
	"context"

	"github.com/sirupsen/logrus"
)

func newTestContext() *VPCContext {
	logger := logrus.New()
	logger.Level = logrus.DebugLevel

	return &VPCContext{
		Context: context.Background(),
		Logger:  logrus.NewEntry(logger),
	}

}

package context

import (
	"container/list"
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func newTestContext() VPCContext {
	logger := logrus.New()
	logger.Level = logrus.DebugLevel

	return &vpcContext{
		Context: context.Background(),
		logger:  logrus.NewEntry(logger),
	}

}

func TestLogger(t *testing.T) {
	logger := logrus.New().WithField("test", "test")
	newAWSLogger := &awsLogger{logger: logger, oldMessages: list.New()}
	newAWSLogger.Log("Test2")
	newAWSLogger.Log("Test1")
	assert.Equal(t, 2, newAWSLogger.oldMessages.Len())
	newAWSLogger.Log("404 - Not Found")
	assert.Equal(t, 0, newAWSLogger.oldMessages.Len())
}

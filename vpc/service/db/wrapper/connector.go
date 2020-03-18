package wrapper

import (
	"context"
	"database/sql/driver"

	"golang.org/x/sync/semaphore"
)

var _ driver.Connector = (*connectorWrapper)(nil)

type wrapper struct {
	serializedConnectionSemaphore *semaphore.Weighted
	hostname                      string
}

type connectorWrapper struct {
	realConnector driver.Connector
	wrapper       *wrapper
}

type ConnectorWrapperConfig struct {
	Hostname                        string
	MaxConcurrentSerialTransactions int64
}

func NewConnectorWrapper(c driver.Connector, config ConnectorWrapperConfig) driver.Connector {
	if config.MaxConcurrentSerialTransactions == 0 {
		config.MaxConcurrentSerialTransactions = 5
	}
	return &connectorWrapper{
		realConnector: c,
		wrapper: &wrapper{
			serializedConnectionSemaphore: semaphore.NewWeighted(config.MaxConcurrentSerialTransactions),
			hostname:                      config.Hostname,
		},
	}
}

func (c *connectorWrapper) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.realConnector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &connectionWrapper{
		realConn: conn.(connectionInterface),
		wrapper:  c.wrapper,
	}, err
}

func (c *connectorWrapper) Driver() driver.Driver {
	return &driverWrapper{
		realDriver: c.realConnector.Driver(),
		wrapper:    c.wrapper,
	}
}

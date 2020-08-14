package wrapper

import (
	"context"
	"database/sql/driver"
	"fmt"

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

	realConn := conn.(connectionInterface)
	rows, err := realConn.QueryContext(ctx, "SELECT pg_backend_pid()", []driver.NamedValue{})
	if err != nil {
		_ = realConn.Close()
		return nil, fmt.Errorf("Could not query pg backend pid: %w", err)
	}
	defer rows.Close()

	var pid int64
	tmpRow := []driver.Value{pid}
	err = rows.Next(tmpRow)
	if err != nil {
		_ = realConn.Close()
		return nil, fmt.Errorf("Could not read pg backend pid: %w", err)
	}

	return &connectionWrapper{
		realConn: conn.(connectionInterface),
		wrapper:  c.wrapper,
		pid:      tmpRow[0].(int64),
	}, nil
}

func (c *connectorWrapper) Driver() driver.Driver {
	return &driverWrapper{
		realDriver: c.realConnector.Driver(),
		wrapper:    c.wrapper,
	}
}

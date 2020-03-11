package wrapper

import (
	"context"
	"database/sql/driver"
)

var _ driver.Connector = (*connectorWrapper)(nil)

type wrapper struct {
	hostname string
}

type connectorWrapper struct {
	realConnector driver.Connector
	wrapper       *wrapper
}

func NewConnectorWrapper(c driver.Connector, hostname string) driver.Connector {
	return &connectorWrapper{
		realConnector: c,
		wrapper: &wrapper{
			hostname: hostname,
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

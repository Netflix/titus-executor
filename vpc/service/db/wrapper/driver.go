package wrapper

import (
	"database/sql/driver"

	"github.com/lib/pq"
)

var (
	_ driverInterface = (*driverWrapper)(nil)
)

type driverInterface interface {
	driver.DriverContext
	driver.Driver
}

type driverWrapper struct {
	realDriver driver.Driver
	hostname   string
}

func (d *driverWrapper) Open(name string) (driver.Conn, error) {
	conn, err := pq.Open(name)
	if err != nil {
		return nil, err
	}
	return &connectionWrapper{
		realConn: conn.(connectionInterface),
		hostname: d.hostname,
	}, err
}

func (d *driverWrapper) OpenConnector(name string) (driver.Connector, error) {
	connector, err := pq.NewConnector(name)
	if err != nil {
		return nil, err
	}
	return &connectorWrapper{
		realConnector: connector,
		hostname:      d.hostname,
	}, err
}

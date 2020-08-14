package wrapper

import (
	"database/sql/driver"
	"fmt"

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
	wrapper    *wrapper
}

func (d *driverWrapper) Open(name string) (driver.Conn, error) {
	conn, err := pq.Open(name)
	if err != nil {
		return nil, err
	}
	realConn := conn.(connectionInterface)
	rows, err := realConn.Query("SELECT pg_backend_pid()", []driver.Value{})
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
		realConn: realConn,
		wrapper:  d.wrapper,
		pid:      tmpRow[0].(int64),
	}, err
}

func (d *driverWrapper) OpenConnector(name string) (driver.Connector, error) {
	connector, err := pq.NewConnector(name)
	if err != nil {
		return nil, err
	}
	return &connectorWrapper{
		realConnector: connector,
		wrapper:       d.wrapper,
	}, err
}

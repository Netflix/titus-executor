package titusmesosdriver

import (
	"net"
	"os"
	"strconv"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/executor/drivers"
	mesosExecutor "github.com/mesos/mesos-go/executor"
	log "github.com/sirupsen/logrus"
)

// TitusMesosDriver interacts withe the Mesos golang driver.
// Wraps the Titus Executor
type TitusMesosDriver struct {
	mesosDriver   mesosExecutor.ExecutorDriver
	titusExecutor titusdriver.TitusExecutor
}

const (
	mesosLibProcessIPKey   = "LIBPROCESS_IP"
	mesosLibProcessPortKey = "LIBPROCESS_PORT"
)

// New allocates a TitusMesosDriver, which includes an allocated Titus executor
// and an allocated Mesos driver.
func New(m metrics.Reporter, executor titusdriver.TitusExecutor) (*TitusMesosDriver, error) {
	// Get required ENV vars that the Mesos slave should have set

	mExecutor := &titusMesosExecutor{
		metrics:       m,
		titusExecutor: executor,
	}
	driverCfg := mesosExecutor.DriverConfig{
		Executor: mExecutor,
	}

	addr := os.Getenv(mesosLibProcessIPKey)
	if addr != "" {
		driverCfg.BindingAddress = net.ParseIP(addr)
	}

	port := os.Getenv(mesosLibProcessPortKey)
	if port != "" {
		portNum, err := strconv.ParseUint(port, 10, 16) // nolint: gas
		if err != nil {
			log.Fatalf("Cannot parse variable %s with value %s", mesosLibProcessPortKey, port)
		}
		driverCfg.BindingPort = uint16(portNum)
	}

	log.Printf("Starting Mesos driver with Driverconfig: %+v", driverCfg)
	//mesosLibProcessIPKey, addr, mesosLibProcessPortKey, portNum)

	mesosDriver, err := mesosExecutor.NewMesosExecutorDriver(driverCfg)
	if err != nil {
		log.Printf("Unable to create ExecutorDriver : %s", err)
		return nil, err
	}
	return &TitusMesosDriver{
		mesosDriver:   mesosDriver,
		titusExecutor: executor,
	}, nil
}

// SetExecutor sets a new executor.
// TODO(Andrew L): Remove this as soon as the mock test is refactored.
func (driver *TitusMesosDriver) SetExecutor(titusExecutor titusdriver.TitusExecutor) {
	driver.titusExecutor = titusExecutor
}

// Start starts the executor driver in the background
func (driver *TitusMesosDriver) Start() error {
	status, err := driver.mesosDriver.Start()
	if err != nil {
		log.Printf("Unable to start ExecutorDriver : %s", err)
		return err
	}
	log.Printf("Started Mesos executor driver with status : %s", status)
	return nil
}

// Stop signals the Mesos Driver to stop its event loop.
// This operation does not block and the actual stopping happens asynchronously.
func (driver *TitusMesosDriver) Stop() error {
	status, err := driver.mesosDriver.Stop()
	log.Infof("Mesos driver stopped. Status: %s : %+v", status, err)
	return err
}

// Join waits for the Mesos driver to terminate.
// This is a blocking call.
func (driver *TitusMesosDriver) Join() error {
	status, err := driver.mesosDriver.Join()
	if err != nil {
		log.Printf("Unable to join on Mesos driver with status %s: %s", status, err)
		return err
	}

	// Stop the executor and cleanup any running containers before we return.
	// This ensures that tasks are cleaned up even if Mesos didn't explicitly
	// trigger a shutdown.
	driver.titusExecutor.Stop()

	log.Printf("Joined on Mesos driver with status %s : %s", status, err)
	return nil
}

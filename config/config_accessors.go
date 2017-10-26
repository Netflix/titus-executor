package config

import (
	"time"
)

// Stack returns the stack configuration variable
func Stack() string {
	configLock.RLock()
	defer configLock.RUnlock()
	return currentConfig.stack
}

// Docker returns the Docker-specific configuration settings
func Docker() docker { // nolint: golint
	configLock.RLock()
	defer configLock.RUnlock()
	return currentConfig.docker
}

// Uploaders returns the uploaders configuration
func Uploaders() uploaders { // nolint: golint
	configLock.RLock()
	defer configLock.RUnlock()
	return currentConfig.uploaders
}

// StatusCheckFrequency returns duration between the periods the executor will poll Dockerd
func StatusCheckFrequency() time.Duration {
	configLock.RLock()
	defer configLock.RUnlock()
	return currentConfig.statusCheckFrequency
}

// DevWorkspace returns the dev workspace specific configuration
func DevWorkspace() devWorkspace { // nolint: golint
	configLock.RLock()
	defer configLock.RUnlock()
	return currentConfig.devWorkspace
}

// UseNewNetworkDriver returns which network driver to use
func UseNewNetworkDriver() bool {
	configLock.RLock()
	defer configLock.RUnlock()
	return currentConfig.useNewNetworkDriver
}

// LogUpload returns settings about the log uploader
func LogUpload() logUpload { // nolint: golint
	configLock.RLock()
	defer configLock.RUnlock()
	return currentConfig.logUpload
}

// PrivilegedContainersEnabled returns whether to give tasks CAP_SYS_ADMIN
func PrivilegedContainersEnabled() bool {
	configLock.RLock()
	defer configLock.RUnlock()
	return currentConfig.privilegedContainersEnabled
}

// MetatronEnabled returns if Metatron is enabled
func MetatronEnabled() bool {
	configLock.RLock()
	defer configLock.RUnlock()
	return currentConfig.metatronEnabled
}

// LogsTmpDir returns the directory which is used by the Docker logging driver
func LogsTmpDir() string {
	configLock.RLock()
	defer configLock.RUnlock()
	return currentConfig.logsTmpDir
}

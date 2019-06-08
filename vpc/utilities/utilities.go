package utilities

import (
	"path/filepath"
	"strconv"
)

// GetLockPath returns the path you should use for locks on this device index
func GetLockPath(idx int) string {
	return filepath.Join("interfaces", strconv.Itoa(idx))
}

func GetConfigurationLockPath(idx int) string {
	return filepath.Join(GetLockPath(idx), "configuration")
}

func GetSecurityGroupLockPath(idx int) string {
	return filepath.Join(GetLockPath(idx), "sg")
}

func GetAddressesLockPath(idx int) string {
	return filepath.Join(GetLockPath(idx), "addresses")
}

// Global configuration lock is taken out exclusively during setup, and GC
func GetGlobalConfigurationLock() string {
	return "global"
}

package config

import (
	"testing"

	"github.com/Netflix/titus-executor/properties"
	"github.com/stretchr/testify/assert"
)

func GetDefaultConfiguration(t *testing.T, args []string) *Config {
	cfg, err := GenerateConfiguration(args)
	assert.NoError(t, err)

	return cfg
}

func TestDefaultLogDir(t *testing.T) {
	//cfg := Load("with-log-upload-config.json")
	cfg := GetDefaultConfiguration(t, nil)
	assert.Equal(t, cfg.LogsTmpDir, "/var/lib/titus-container-logs", "Log dir set to unexpected value")
}

func TestDefaults(t *testing.T) {
	cfg := GetDefaultConfiguration(t, nil)

	assert.Equal(t, cfg.Stack, "mainvpc")

}

func TestHardCodedEnvironment2(t *testing.T) {
	cfg := GetDefaultConfiguration(t, []string{"--hard-coded-env", "FOO=BAR", "--hard-coded-env", "BAZ=QUUX"})
	assert.Contains(t, cfg.hardCodedEnv, "FOO=BAR")
	assert.Contains(t, cfg.hardCodedEnv, "BAZ=QUUX")

}

func TestFlags(t *testing.T) {
	_, flags := NewConfig()
	properties.ConvertFlagsForAltSrc(flags)
}

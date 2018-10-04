package docker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidation(t *testing.T) {
	cfg := new(Config)

	// CFS Bandwidth Validation
	cfg.cfsBandwidthPeriod = minCfsBandwidth - 1
	assert.Error(t, validate(cfg))

	cfg.cfsBandwidthPeriod = minCfsBandwidth
	assert.NoError(t, validate(cfg))

	cfg.cfsBandwidthPeriod = minCfsBandwidth + 1
	assert.NoError(t, validate(cfg))

	cfg.cfsBandwidthPeriod = maxCfsBandwidth - 1
	assert.NoError(t, validate(cfg))

	cfg.cfsBandwidthPeriod = maxCfsBandwidth
	assert.NoError(t, validate(cfg))

	cfg.cfsBandwidthPeriod = maxCfsBandwidth + 1
	assert.Error(t, validate(cfg))
}

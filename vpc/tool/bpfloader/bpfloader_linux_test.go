// +build linux

package bpfloader

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	if os.Getenv("CIRCLECI") == "true" {
		t.Skip("Test does not work on Travis")
	}
	reader, err := os.Open("testdata/filter.o")
	assert.NoError(t, err)
	_, err = GetProgram(reader, "classifier_ingress")
	assert.NoError(t, err)
}

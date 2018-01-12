// +build linux

package bpfloader

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	reader, err := os.Open("testdata/filter.o")
	assert.NoError(t, err)
	_, err = GetProgram(reader, "classifier_ingress")
	assert.NoError(t, err)
}

//go:build linux
// +build linux

package bpfloader

import (
	"io/ioutil"
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	if os.Getenv("CIRCLECI") == "true" {
		t.Skip("Test does not work on Travis")
	}

	disabledStr, err := ioutil.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled")
	assert.NoError(t, err)

	disabled, err := strconv.Atoi(strings.TrimSpace(string(disabledStr)))
	assert.NoError(t, err)

	u, err := user.Current()
	assert.NoError(t, err)

	uid, err := strconv.Atoi(u.Uid)
	assert.NoError(t, err)

	if disabled != 0 && uid != 0 {
		t.Skip("unprivileged bpf is not allowed and not root")
	}

	reader, err := os.Open("testdata/filter.o")
	assert.NoError(t, err)
	_, err = GetProgram(reader, "classifier_ingress")
	assert.NoError(t, err)
}

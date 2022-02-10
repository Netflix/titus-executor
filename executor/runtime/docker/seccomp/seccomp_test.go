//go:build cgo
// +build cgo

// These tests require CGO (unfortunately) because libseccomp does
// These build flags mean that these tests are not normally run during
// our normal test suites (which do not use CGO)
// These are designed to be run from "make test" in the seccomp directory

package seccomp

import (
	"testing"

	dockerSeccomp "github.com/docker/docker/profiles/seccomp"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
)

func getGenericDockerSpec() specs.Spec {
	rs := specs.Spec{}
	rs.Process = &specs.Process{}
	rs.Process.Capabilities = &specs.LinuxCapabilities{}
	rs.Process.Capabilities.Bounding = []string{}
	return rs
}

func TestAllProfilesLoad(t *testing.T) {
	rs := getGenericDockerSpec()
	for _, name := range AssetNames() {
		t.Logf("Loading seccomp profile for %s", name)
		a, err := Asset(name)
		assert.NoError(t, err)
		// The "json files" (compiled into seccomp bin data) are a docker-specific
		// format, so we must use docker's seccomp profile loading library to ensure
		// they are valid.
		profile, err := dockerSeccomp.LoadProfile(string(a), &rs)
		assert.NoError(t, err)
		assert.NotNil(t, profile)
	}
}

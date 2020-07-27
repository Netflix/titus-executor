package gc3

import (
	"io/ioutil"
	"sort"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestGetKubernetesTasks(t *testing.T) {
	body, err := ioutil.ReadFile("testdata/pods.json")
	assert.NilError(t, err)

	tasks, err := parseKubernetesTasksBody(body)
	assert.NilError(t, err)
	sort.Strings(tasks)
	assert.Assert(t, is.DeepEqual([]string{
		"a0874a5c-f4c1-4817-b12d-6a28335070ab",
	}, tasks))
}

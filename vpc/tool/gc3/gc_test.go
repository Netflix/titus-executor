package gc3

import (
	"io/ioutil"
	"sort"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestGetMesosTasks(t *testing.T) {
	body, err := ioutil.ReadFile("testdata/state.json")
	assert.NilError(t, err)

	tasks, err := parseMesosTasksBody(body)
	assert.NilError(t, err)
	sort.Strings(tasks)
	assert.Assert(t, is.DeepEqual([]string{
		"23e683ca-2673-4ecc-a4c5-a8eb6655abcc",
		"47cbe9a7-6606-45e0-8df1-ff9c6ea1d954",
		"4f32f718-40a0-43ec-a667-bf8f02cf6d04",
		"a637446c-3252-4c89-9ee6-159b4c34b476",
		"bc53f717-2c1f-415a-8af0-df8a67f15ce7",
	}, tasks))
}

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

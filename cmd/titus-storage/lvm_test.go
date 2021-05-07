package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVGSOutputAndSize(t *testing.T) {

	// vgs really does output these leading spaces
	mockOutput := `  {
      "report": [
          {
              "vg": [
                  {"vg_name":"ephemeral", "pv_count":"1", "lv_count":"0", "snap_count":"0", "vg_attr":"wz--n-", "vg_size":"1799.72G", "vg_free":"19.72G"}
              ]
          }
      ]
  }`
	var vgsOputput vgsOutputStructure
	_ = json.Unmarshal([]byte(mockOutput), &vgsOputput)
	actual, err := getVGSize(vgsOputput, "ephemeral")
	expected := 1800
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestCalculateEphemeralStorageSizeGB(t *testing.T) {
	gpusRequested := 1
	totalGpus := 8
	totalVGSizeGB := 8000 + reservedVGSpaceGB
	actual := calculateEphemeralStorageSizeGB(gpusRequested, totalGpus, totalVGSizeGB)
	assert.Equal(t, 1000, actual)
}

func TestCalculateEphemeralStorageSizeGBEverything(t *testing.T) {
	gpusRequested := 8
	totalGpus := 8
	totalVGSizeGB := 8000 + reservedVGSpaceGB
	actual := calculateEphemeralStorageSizeGB(gpusRequested, totalGpus, totalVGSizeGB)
	assert.Equal(t, 8000, actual)
}

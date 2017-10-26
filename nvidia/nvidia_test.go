package nvidia

import (
	"fmt"
	"regexp"
	"testing"
)

const (
	g2 = "g2.8xlarge"
	p2 = "p2.8xlarge"

	m4 = "m4.4xlarge"
	r3 = "rx.8xlarge"
)

func TestRexexp(t *testing.T) {
	gpuTypes := [...]string{g2, p2}
	nonGpuTypes := [...]string{m4, r3}
	r := regexp.MustCompile(AwsGpuInstanceRegex)

	for _, gpuType := range gpuTypes {
		if r.MatchString(gpuType) {
			t.Log(fmt.Sprintf("Matched %s", gpuType))
		} else {
			t.Fatal(fmt.Errorf("Failed to match %s", gpuType))
		}
	}

	for _, nonGpuType := range nonGpuTypes {
		if r.MatchString(nonGpuType) {
			t.Fatal(fmt.Errorf("Incorrectly matched %s", nonGpuType))
		} else {
			t.Log(fmt.Sprintf("Correctly did not match %s", nonGpuType))
		}
	}
}

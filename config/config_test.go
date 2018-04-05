package config

import (
	"testing"

	titusproto "github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/golang/protobuf/proto"
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

func TestDefaultDurations(t *testing.T) {
	cfg := GetDefaultConfiguration(t, nil)

	assert.Equal(t, cfg.Stack, "mainvpc")
	assert.Equal(t, cfg.LogUploadThresholdTime, defaultLogUploadThreshold)
	assert.Equal(t, cfg.LogUploadCheckInterval, defaultLogUploadCheckInterval)

}

func TestClusterName(t *testing.T) {
	fixtures := []struct {
		input *titusproto.ContainerInfo
		want  string
	}{
		{
			input: &titusproto.ContainerInfo{
				AppName:        proto.String("app1"),
				JobGroupStack:  proto.String("somestack"),
				JobGroupDetail: proto.String("details"),
			},
			want: "app1-somestack-details",
		},
		{
			// no details
			input: &titusproto.ContainerInfo{
				AppName:       proto.String("app2"),
				JobGroupStack: proto.String("somestack"),
			},
			want: "app2-somestack",
		},
		{
			// no stack
			input: &titusproto.ContainerInfo{
				AppName:        proto.String("app3"),
				JobGroupDetail: proto.String("details"),
			},
			want: "app3--details",
		},
		{
			// no stack no details
			input: &titusproto.ContainerInfo{
				AppName: proto.String("app4"),
			},
			want: "app4",
		},
	}

	for _, f := range fixtures {
		if got := combineAppStackDetails(f.input, *f.input.AppName); got != f.want {
			t.Fatalf("want: %s, got %s", f.want, got)
		}
	}
}

func TestHardCodedEnvironment(t *testing.T) {
	cfg := GetDefaultConfiguration(t, nil)
	assert.Contains(t, cfg.HardCodedEnv, "EC2_DOMAIN=amazonaws.com")
}

func TestHardCodedEnvironment2(t *testing.T) {
	cfg := GetDefaultConfiguration(t, []string{"--hard-coded-env", "FOO=BAR", "--hard-coded-env", "BAZ=QUUX"})
	assert.Contains(t, cfg.HardCodedEnv, "FOO=BAR")
	assert.Contains(t, cfg.HardCodedEnv, "BAZ=QUUX")

}

func TestEnvBasedOnTaskInfo(t *testing.T) {
	type input struct {
		info                             *titusproto.ContainerInfo
		cpu, mem, disk, networkBandwidth string
	}
	check := func(input input, want map[string]string) func(*testing.T) {
		return func(t *testing.T) {
			cfg := GetDefaultConfiguration(t, nil)
			got := cfg.getEnvBasedOnTask(input.info, input.mem, input.cpu, input.disk, input.networkBandwidth)
			if len(got) != len(want) {
				t.Fatalf("expected: %+v, got: %+v", want, got)
			}
			for k, w := range want {
				if g, ok := got[k]; !ok || g != w {
					t.Fatalf("expected %q for key %s, got %q", w, k, g)
				}
			}
		}
	}

	fixtures := []struct {
		name  string
		input input
		want  map[string]string
	}{
		{
			name: "Full",
			input: input{
				info: &titusproto.ContainerInfo{
					AppName:          proto.String("app1"),
					ImageName:        proto.String("image1"),
					JobGroupStack:    proto.String("stack1"),
					JobGroupDetail:   proto.String("detail1"),
					JobGroupSequence: proto.String("v001"),
				},
				cpu:              "1",
				mem:              "100",
				disk:             "1000",
				networkBandwidth: "100",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "app1",
				"NETFLIX_STACK":               "stack1",
				"NETFLIX_DETAIL":              "detail1",
				"NETFLIX_CLUSTER":             "app1-stack1-detail1",
				"NETFLIX_AUTO_SCALE_GROUP":    "app1-stack1-detail1-v001",
				"TITUS_NUM_CPU":               "1",
				"TITUS_NUM_MEM":               "100",
				"TITUS_NUM_DISK":              "1000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "100",
			},
		},
		{
			name: "NoName",
			input: input{
				info: &titusproto.ContainerInfo{
					ImageName:        proto.String("image1"),
					JobGroupStack:    proto.String("stack1"),
					JobGroupDetail:   proto.String("detail1"),
					JobGroupSequence: proto.String("v001"),
				},
				cpu:              "2",
				mem:              "200",
				disk:             "2000",
				networkBandwidth: "200",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "image1",
				"NETFLIX_STACK":               "stack1",
				"NETFLIX_DETAIL":              "detail1",
				"NETFLIX_CLUSTER":             "image1-stack1-detail1",
				"NETFLIX_AUTO_SCALE_GROUP":    "image1-stack1-detail1-v001",
				"TITUS_NUM_CPU":               "2",
				"TITUS_NUM_MEM":               "200",
				"TITUS_NUM_DISK":              "2000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "200",
			},
		},
		{
			name: "NoStack",
			input: input{
				info: &titusproto.ContainerInfo{
					AppName:          proto.String("app1"),
					ImageName:        proto.String("image1"),
					JobGroupDetail:   proto.String("detail1"),
					JobGroupSequence: proto.String("v001"),
				},
				cpu:              "3",
				mem:              "300",
				disk:             "3000",
				networkBandwidth: "300",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "app1",
				"NETFLIX_DETAIL":              "detail1",
				"NETFLIX_STACK":               "",
				"NETFLIX_CLUSTER":             "app1--detail1",
				"NETFLIX_AUTO_SCALE_GROUP":    "app1--detail1-v001",
				"TITUS_NUM_CPU":               "3",
				"TITUS_NUM_MEM":               "300",
				"TITUS_NUM_DISK":              "3000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "300",
			},
		},
		{
			name: "NoDetail",
			input: input{
				info: &titusproto.ContainerInfo{
					AppName:          proto.String("app1"),
					ImageName:        proto.String("image1"),
					JobGroupStack:    proto.String("stack1"),
					JobGroupSequence: proto.String("v001"),
				},
				cpu:              "4",
				mem:              "400",
				disk:             "4000",
				networkBandwidth: "400",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "app1",
				"NETFLIX_STACK":               "stack1",
				"NETFLIX_DETAIL":              "",
				"NETFLIX_CLUSTER":             "app1-stack1",
				"NETFLIX_AUTO_SCALE_GROUP":    "app1-stack1-v001",
				"TITUS_NUM_CPU":               "4",
				"TITUS_NUM_MEM":               "400",
				"TITUS_NUM_DISK":              "4000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "400",
			},
		},
		{
			name: "NoSequence",
			input: input{
				info: &titusproto.ContainerInfo{
					AppName:        proto.String("app1"),
					ImageName:      proto.String("image1"),
					JobGroupStack:  proto.String("stack1"),
					JobGroupDetail: proto.String("detail1"),
				},
				cpu:              "5",
				mem:              "500",
				disk:             "5000",
				networkBandwidth: "500",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "app1",
				"NETFLIX_STACK":               "stack1",
				"NETFLIX_DETAIL":              "detail1",
				"NETFLIX_CLUSTER":             "app1-stack1-detail1",
				"NETFLIX_AUTO_SCALE_GROUP":    "app1-stack1-detail1-v000",
				"TITUS_NUM_CPU":               "5",
				"TITUS_NUM_MEM":               "500",
				"TITUS_NUM_DISK":              "5000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "500",
			},
		},
		{
			name: "NoStackNoDetail",
			input: input{
				info: &titusproto.ContainerInfo{
					AppName:          proto.String("app1"),
					ImageName:        proto.String("image1"),
					JobGroupSequence: proto.String("v001"),
				},
				cpu:              "6",
				mem:              "600",
				disk:             "6000",
				networkBandwidth: "600",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "app1",
				"NETFLIX_STACK":               "",
				"NETFLIX_DETAIL":              "",
				"NETFLIX_CLUSTER":             "app1",
				"NETFLIX_AUTO_SCALE_GROUP":    "app1-v001",
				"TITUS_NUM_CPU":               "6",
				"TITUS_NUM_MEM":               "600",
				"TITUS_NUM_DISK":              "6000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "600",
			},
		},
		{
			name: "NoStackNoDetailNoSequence",
			input: input{
				info: &titusproto.ContainerInfo{
					AppName:   proto.String("app1"),
					ImageName: proto.String("image1"),
				},
				cpu:              "7",
				mem:              "700",
				disk:             "7000",
				networkBandwidth: "700",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "app1",
				"NETFLIX_STACK":               "",
				"NETFLIX_DETAIL":              "",
				"NETFLIX_CLUSTER":             "app1",
				"NETFLIX_AUTO_SCALE_GROUP":    "app1-v000",
				"TITUS_NUM_CPU":               "7",
				"TITUS_NUM_MEM":               "700",
				"TITUS_NUM_DISK":              "7000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "700",
			},
		},
		{
			name: "NoNameNoStackNoDetailNoSequence",
			input: input{
				info: &titusproto.ContainerInfo{
					ImageName: proto.String("image1"),
				},
				cpu:              "8",
				mem:              "800",
				disk:             "8000",
				networkBandwidth: "800",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "image1",
				"NETFLIX_STACK":               "",
				"NETFLIX_DETAIL":              "",
				"NETFLIX_CLUSTER":             "image1",
				"NETFLIX_AUTO_SCALE_GROUP":    "image1-v000",
				"TITUS_NUM_CPU":               "8",
				"TITUS_NUM_MEM":               "800",
				"TITUS_NUM_DISK":              "8000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "800",
			},
		},
	}

	for _, f := range fixtures {
		t.Run(f.name, check(f.input, f.want))
	}
}

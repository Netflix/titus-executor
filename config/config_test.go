package config

import (
	"testing"
	"time"

	titusproto "github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/golang/protobuf/proto"
)

func TestDefaultLogDir(t *testing.T) {
	Load("with-log-upload-config.json")

	if logDirTempVal := LogsTmpDir(); logDirTempVal != "/var/lib/titus-container-logs" {
		t.Fatal("Log dir set to unexpected value: ", logDirTempVal)
	}
}
func TestDefaultDurations(t *testing.T) {
	Load("no-log-upload-config.json")
	if Stack() == "" {
		t.Fatalf("Stack empty")
	}
	if LogUpload().LogUploadThresholdTime != 6*time.Hour {
		t.Fatalf("LogUploadThresholdTime default incorrect")
	}

	if LogUpload().LogUploadCheckInterval != 15*time.Minute {
		t.Fatalf("LogUploadCheckInterval default incorrect")
	}
}

func TestConfiguredDurations(t *testing.T) {
	Load("with-log-upload-config.json")
	if Stack() == "" {
		t.Fatalf("Stack empty")
	}
	if LogUpload().LogUploadThresholdTime != 1*time.Millisecond {
		t.Fatalf("LogUploadThresholdTime should be 0")
	}

	if LogUpload().LogUploadCheckInterval != 10*time.Second {
		t.Fatalf("LogUploadCheckInterval should be %v", 10*time.Second)
	}
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

func TestEnvBasedOnTaskInfo(t *testing.T) {
	type input struct {
		info           *titusproto.ContainerInfo
		cpu, mem, disk string
	}
	check := func(input input, want map[string]string) func(*testing.T) {
		return func(t *testing.T) {
			got := getEnvBasedOnTask(input.info, input.mem, input.cpu, input.disk)
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
				cpu:  "1",
				mem:  "100",
				disk: "1000",
			},
			want: map[string]string{
				"NETFLIX_APP":              "app1",
				"NETFLIX_STACK":            "stack1",
				"NETFLIX_DETAIL":           "detail1",
				"NETFLIX_CLUSTER":          "app1-stack1-detail1",
				"NETFLIX_AUTO_SCALE_GROUP": "app1-stack1-detail1-v001",
				"TITUS_NUM_CPU":            "1",
				"TITUS_NUM_MEM":            "100",
				"TITUS_NUM_DISK":           "1000",
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
				cpu:  "2",
				mem:  "200",
				disk: "2000",
			},
			want: map[string]string{
				"NETFLIX_APP":              "image1",
				"NETFLIX_STACK":            "stack1",
				"NETFLIX_DETAIL":           "detail1",
				"NETFLIX_CLUSTER":          "image1-stack1-detail1",
				"NETFLIX_AUTO_SCALE_GROUP": "image1-stack1-detail1-v001",
				"TITUS_NUM_CPU":            "2",
				"TITUS_NUM_MEM":            "200",
				"TITUS_NUM_DISK":           "2000",
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
				cpu:  "3",
				mem:  "300",
				disk: "3000",
			},
			want: map[string]string{
				"NETFLIX_APP":              "app1",
				"NETFLIX_DETAIL":           "detail1",
				"NETFLIX_STACK":            "",
				"NETFLIX_CLUSTER":          "app1--detail1",
				"NETFLIX_AUTO_SCALE_GROUP": "app1--detail1-v001",
				"TITUS_NUM_CPU":            "3",
				"TITUS_NUM_MEM":            "300",
				"TITUS_NUM_DISK":           "3000",
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
				cpu:  "4",
				mem:  "400",
				disk: "4000",
			},
			want: map[string]string{
				"NETFLIX_APP":              "app1",
				"NETFLIX_STACK":            "stack1",
				"NETFLIX_DETAIL":           "",
				"NETFLIX_CLUSTER":          "app1-stack1",
				"NETFLIX_AUTO_SCALE_GROUP": "app1-stack1-v001",
				"TITUS_NUM_CPU":            "4",
				"TITUS_NUM_MEM":            "400",
				"TITUS_NUM_DISK":           "4000",
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
				cpu:  "5",
				mem:  "500",
				disk: "5000",
			},
			want: map[string]string{
				"NETFLIX_APP":              "app1",
				"NETFLIX_STACK":            "stack1",
				"NETFLIX_DETAIL":           "detail1",
				"NETFLIX_CLUSTER":          "app1-stack1-detail1",
				"NETFLIX_AUTO_SCALE_GROUP": "app1-stack1-detail1-v000",
				"TITUS_NUM_CPU":            "5",
				"TITUS_NUM_MEM":            "500",
				"TITUS_NUM_DISK":           "5000",
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
				cpu:  "6",
				mem:  "600",
				disk: "6000",
			},
			want: map[string]string{
				"NETFLIX_APP":              "app1",
				"NETFLIX_STACK":            "",
				"NETFLIX_DETAIL":           "",
				"NETFLIX_CLUSTER":          "app1",
				"NETFLIX_AUTO_SCALE_GROUP": "app1-v001",
				"TITUS_NUM_CPU":            "6",
				"TITUS_NUM_MEM":            "600",
				"TITUS_NUM_DISK":           "6000",
			},
		},
		{
			name: "NoStackNoDetailNoSequence",
			input: input{
				info: &titusproto.ContainerInfo{
					AppName:   proto.String("app1"),
					ImageName: proto.String("image1"),
				},
				cpu:  "7",
				mem:  "700",
				disk: "7000",
			},
			want: map[string]string{
				"NETFLIX_APP":              "app1",
				"NETFLIX_STACK":            "",
				"NETFLIX_DETAIL":           "",
				"NETFLIX_CLUSTER":          "app1",
				"NETFLIX_AUTO_SCALE_GROUP": "app1-v000",
				"TITUS_NUM_CPU":            "7",
				"TITUS_NUM_MEM":            "700",
				"TITUS_NUM_DISK":           "7000",
			},
		},
		{
			name: "NoNameNoStackNoDetailNoSequence",
			input: input{
				info: &titusproto.ContainerInfo{
					ImageName: proto.String("image1"),
				},
				cpu:  "8",
				mem:  "800",
				disk: "8000",
			},
			want: map[string]string{
				"NETFLIX_APP":              "image1",
				"NETFLIX_STACK":            "",
				"NETFLIX_DETAIL":           "",
				"NETFLIX_CLUSTER":          "image1",
				"NETFLIX_AUTO_SCALE_GROUP": "image1-v000",
				"TITUS_NUM_CPU":            "8",
				"TITUS_NUM_MEM":            "800",
				"TITUS_NUM_DISK":           "8000",
			},
		},
	}

	for _, f := range fixtures {
		t.Run(f.name, check(f.input, f.want))
	}
}

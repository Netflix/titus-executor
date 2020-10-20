module github.com/Netflix/titus-executor

go 1.13

require (
	cloud.google.com/go v0.53.0 // indirect
	contrib.go.opencensus.io/exporter/zipkin v0.1.1
	github.com/DATA-DOG/go-sqlmock v1.4.1
	github.com/DataDog/datadog-go v3.4.0+incompatible // indirect
	github.com/Datadog/opencensus-go-exporter-datadog v0.0.0-20190503082300-0f32ad59ab08
	github.com/Netflix/metrics-client-go v0.0.0-20171019173821-bb173f41fc07
	github.com/Netflix/spectator-go v0.0.0-20190913215732-d4e0463555ef
	github.com/Netflix/titus-api-definitions v0.0.1-rc9.0.20200520235959-0ab6f1129886
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/alessio/shellescape v0.0.0-20190409004728-b115ca0f9053 // indirect
	github.com/apparentlymart/go-cidr v1.0.0
	github.com/aws/aws-sdk-go v1.35.10
	github.com/bombsimon/wsl/v2 v2.1.0 // indirect
	github.com/containernetworking/cni v0.7.1
	github.com/coreos/go-systemd v0.0.0-20200109085637-d657f9650837
	github.com/cyphar/filepath-securejoin v0.2.2
	github.com/deckarep/golang-set v1.7.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/docker v0.7.3-0.20190327010347-be7ac8be2ae0
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0
	github.com/fatih/color v1.9.0 // indirect
	github.com/ftrvxmtrx/fd v0.0.0-20150925145434-c6d800382fff
	github.com/gogo/protobuf v1.3.1
	github.com/golang-migrate/migrate v3.5.4+incompatible
	github.com/golang/protobuf v1.3.3
	github.com/golangci/gocyclo v0.0.0-20180528144436-0a533e8fa43d // indirect
	github.com/golangci/golangci-lint v1.23.6
	github.com/golangci/revgrep v0.0.0-20180812185044-276a5c0a1039 // indirect
	github.com/google/uuid v1.1.2
	github.com/gopherjs/gopherjs v0.0.0-20200217142428-fce0ec30dd00 // indirect
	github.com/gorilla/mux v1.7.4
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0
	github.com/hashicorp/go-multierror v1.0.1-0.20191120192120-72917a1559e1
	github.com/jirfag/go-printf-func-name v0.0.0-20200119135958-7558a9eaa5af // indirect
	github.com/jmespath/go-jmespath v0.4.0
	github.com/json-iterator/go v1.1.9 // indirect
	github.com/jteeuwen/go-bindata v3.0.7+incompatible
	github.com/karlseguin/ccache/v2 v2.0.7-0.20200814031513-0dbf3f125f13
	github.com/kr/text v0.2.0 // indirect
	github.com/leanovate/gopter v0.0.0-20170420174722-9e6101e5a875
	github.com/lib/pq v1.3.0
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/myitcv/gobin v0.0.9
	github.com/netflix-skunkworks/opencensus-go-exporter-datadog v0.0.0-20190911150647-ef71dde58796
	github.com/opencontainers/runc v1.0.0-rc10
	github.com/opencontainers/runtime-spec v1.0.1 // indirect
	github.com/openzipkin/zipkin-go v0.2.2
	github.com/pelletier/go-toml v1.6.0 // indirect
	github.com/pkg/errors v0.9.1
	github.com/rogpeppe/go-internal v1.5.2 // indirect
	github.com/securego/gosec v0.0.0-20200203094520-d13bb6d2420c // indirect
	github.com/shurcooL/go v0.0.0-20191216061654-b114cc39af9f // indirect
	github.com/sirupsen/logrus v1.7.0
	github.com/smartystreets/assertions v1.0.1 // indirect
	github.com/soheilhy/cmux v0.1.4
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v0.0.6
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.6.2
	github.com/stretchr/testify v1.5.1
	github.com/tommy-muehle/go-mnd v1.2.0 // indirect
	github.com/virtual-kubelet/virtual-kubelet v1.0.0
	github.com/vishvananda/netlink v1.0.1-0.20190930145447-2ec5bdc52b86
	github.com/vishvananda/netns v0.0.0-20180720170159-13995c7128cc
	github.com/wercker/journalhook v0.0.0-20180428041537-5d0a5ae867b3
	go.opencensus.io v0.22.3
	go.uber.org/multierr v1.1.0
	golang.org/x/crypto v0.0.0-20200221170553-0f24fbd83dfb
	golang.org/x/net v0.0.0-20200219183655-46282727080f
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/sys v0.0.0-20200219091948-cb0a6d8edb6c
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	golang.org/x/tools v0.0.0-20200221191710-57f3fb51f507
	google.golang.org/genproto v0.0.0-20200218151345-dad8c97a84f5 // indirect
	google.golang.org/grpc v1.27.1
	gopkg.in/alessio/shellescape.v1 v1.0.0-20170105083845-52074bc9df61
	gopkg.in/ini.v1 v1.52.0 // indirect
	gopkg.in/urfave/cli.v1 v1.20.0
	gotest.tools v2.2.0+incompatible
	honnef.co/go/tools v0.0.1-2020.1.2 // indirect

	k8s.io/api v0.18.4
	k8s.io/apimachinery v0.18.4
	k8s.io/client-go v10.0.0+incompatible
	k8s.io/kubernetes v1.18.4
	mvdan.cc/unparam v0.0.0-20191111180625-960b1ec0f2c2 // indirect
	sourcegraph.com/sqs/pbtypes v1.0.0 // indirect
)

replace github.com/docker/docker => github.com/moby/moby v0.0.0-20190408150954-50ebe4562dfc

replace github.com/coreos/go-systemd => github.com/coreos/go-systemd/v22 v22.0.0

replace sourcegraph.com/sqs/pbtypes => github.com/sqs/pbtypes v1.0.0

replace k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.18.4

replace k8s.io/cloud-provider => k8s.io/cloud-provider v0.18.4

replace k8s.io/cli-runtime => k8s.io/cli-runtime v0.18.4

replace k8s.io/apiserver => k8s.io/apiserver v0.18.4

replace k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.18.4

replace k8s.io/cri-api => k8s.io/cri-api v0.18.4

replace k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.18.4

replace k8s.io/kubelet => k8s.io/kubelet v0.18.4

replace k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.18.4

replace k8s.io/apimachinery => k8s.io/apimachinery v0.18.4

replace k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.18.4

replace k8s.io/kube-proxy => k8s.io/kube-proxy v0.18.4

replace k8s.io/component-base => k8s.io/component-base v0.18.4

replace k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.18.4

replace k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.18.4

replace k8s.io/metrics => k8s.io/metrics v0.18.4

replace k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.18.4

replace k8s.io/code-generator => k8s.io/code-generator v0.18.4

replace k8s.io/client-go => k8s.io/client-go v0.18.4

replace k8s.io/kubectl => k8s.io/kubectl v0.18.4

replace k8s.io/api => k8s.io/api v0.18.4

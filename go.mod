module github.com/Netflix/titus-executor

go 1.12

replace github.com/docker/docker => github.com/docker/engine v0.0.0-20190408150954-50ebe4562dfc

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Microsoft/go-winio v0.3.8 // indirect
	github.com/Netflix/metrics-client-go v0.0.0-20171019173821-bb173f41fc07
	github.com/Netflix/titus-api-definitions v0.0.0-20190122230735-8229582b5675
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/alessio/shellescape v0.0.0-20190409004728-b115ca0f9053 // indirect
	github.com/apparentlymart/go-cidr v0.0.0-20170616213631-2bd8b58cf427
	github.com/aws/aws-sdk-go v1.19.15
	github.com/coreos/go-systemd v0.0.0-20180511133405-39ca1b05acc7
	github.com/cyphar/filepath-securejoin v0.0.0-20190205144030-7efe413b52e1
	github.com/deckarep/golang-set v0.0.0-20180603214616-504e848d77ea
	github.com/docker/distribution v0.0.0-20170303212246-08b06dc02367 // indirect
	github.com/docker/docker v0.7.3-0.20190327010347-be7ac8be2ae0
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.3.3
	github.com/fatih/color v1.7.0 // indirect
	github.com/ftrvxmtrx/fd v0.0.0-20150925145434-c6d800382fff
	github.com/godbus/dbus v4.1.0+incompatible // indirect
	github.com/gogo/protobuf v1.2.1
	github.com/golang/protobuf v1.3.1
	github.com/golangci/golangci-lint v1.16.0
	github.com/gorilla/context v1.1.1 // indirect
	github.com/gorilla/mux v1.6.2
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/jteeuwen/go-bindata v3.0.7+incompatible
	github.com/leanovate/gopter v0.0.0-20170420174722-9e6101e5a875
	github.com/mesos/mesos-go v0.0.0-20161004192122-7228b13084ce
	github.com/mitchellh/mapstructure v1.1.2 // indirect
	github.com/myitcv/gobin v0.0.9
	github.com/opencontainers/go-digest v1.0.0-rc0 // indirect
	github.com/opencontainers/image-spec v0.0.0-20190321123305-da296dcb1e47 // indirect
	github.com/opencontainers/runc v0.0.0-20180125150909-c4e4bb0df2fc
	github.com/opencontainers/runtime-spec v1.0.1 // indirect
	github.com/pborman/uuid v1.2.0
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.4.1
	github.com/spf13/afero v1.2.2 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.3.0
	github.com/virtual-kubelet/virtual-kubelet v0.10.0
	github.com/vishvananda/netlink v0.0.0-20180205182215-a2af46a09c21
	github.com/vishvananda/netns v0.0.0-20160430053723-8ba1072b58e0
	github.com/wercker/journalhook v0.0.0-20180428041537-5d0a5ae867b3
	golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3 // indirect
	golang.org/x/sync v0.0.0-20190227155943-e225da77a7e6
	golang.org/x/sys v0.0.0-20190403152447-81d4e9dc473e
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4 // indirect
	golang.org/x/tools v0.0.0-20190328211700-ab21143f2384
	google.golang.org/appengine v1.4.0 // indirect
	google.golang.org/genproto v0.0.0-20190404172233-64821d5d2107 // indirect
	google.golang.org/grpc v1.20.1 // indirect
	gopkg.in/alessio/shellescape.v1 v1.0.0-20170105083845-52074bc9df61
	gopkg.in/urfave/cli.v1 v1.20.0
	gotest.tools v2.2.0+incompatible // indirect
	k8s.io/api v0.0.0-20190624085159-95846d7ef82a
)

replace go.opencensus.io => go.opencensus.io v0.20.2

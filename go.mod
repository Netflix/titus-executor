module github.com/Netflix/titus-executor

go 1.12

replace github.com/docker/docker => github.com/docker/engine v0.0.0-20190408150954-50ebe4562dfc

require (
	github.com/Azure/azure-sdk-for-go v28.1.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.1.0 // indirect
	github.com/Azure/go-autorest/autorest/to v0.1.0 // indirect
	github.com/Microsoft/go-winio v0.3.8 // indirect
	github.com/Netflix/metrics-client-go v0.0.0-20171019173821-bb173f41fc07
	github.com/Netflix/titus-api-definitions v0.0.0-20190122230735-8229582b5675
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/alessio/shellescape v0.0.0-20190409004728-b115ca0f9053 // indirect
	github.com/aliyun/alibaba-cloud-sdk-go v0.0.0-20190505033532-d15efc607c82 // indirect
	github.com/apparentlymart/go-cidr v0.0.0-20170616213631-2bd8b58cf427
	github.com/aws/aws-sdk-go v1.19.15
	github.com/cenkalti/backoff v2.1.1+incompatible // indirect
	github.com/coreos/go-systemd v0.0.0-20180511133405-39ca1b05acc7
	github.com/cpuguy83/strongerrors v0.2.1
	github.com/cyphar/filepath-securejoin v0.0.0-20190205144030-7efe413b52e1
	github.com/deckarep/golang-set v0.0.0-20180603214616-504e848d77ea
	github.com/docker/distribution v0.0.0-20170303212246-08b06dc02367 // indirect
	github.com/docker/docker v0.7.3-0.20190327010347-be7ac8be2ae0
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.3.3
	github.com/ftrvxmtrx/fd v0.0.0-20150925145434-c6d800382fff
	github.com/godbus/dbus v4.1.0+incompatible // indirect
	github.com/gogo/protobuf v1.2.1
	github.com/golang/protobuf v1.3.1
	github.com/golangci/golangci-lint v1.16.0
	github.com/gophercloud/gophercloud v0.0.0-20190504011306-6f9faf57fddc // indirect
	github.com/gorilla/mux v1.6.2
	github.com/gregjones/httpcache v0.0.0-20190212212710-3befbb6ad0cc // indirect
	github.com/hashicorp/consul v1.4.4 // indirect
	github.com/hashicorp/consul/api v1.0.1 // indirect
	github.com/hashicorp/go-hclog v0.9.0 // indirect
	github.com/hashicorp/go-msgpack v0.5.5 // indirect
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/hashicorp/nomad v0.9.1 // indirect
	github.com/hashicorp/nomad/api v0.0.0-20190506224252-9ef81dbe7f27 // indirect
	github.com/hashicorp/raft v1.0.1 // indirect
	github.com/hashicorp/vault/api v1.0.1 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/jteeuwen/go-bindata v3.0.7+incompatible
	github.com/lawrencegripper/pod2docker v0.5.2 // indirect
	github.com/leanovate/gopter v0.0.0-20170420174722-9e6101e5a875
	github.com/mesos/mesos-go v0.0.0-20161004192122-7228b13084ce
	github.com/myitcv/gobin v0.0.9
	github.com/opencontainers/go-digest v1.0.0-rc0 // indirect
	github.com/opencontainers/image-spec v0.0.0-20190321123305-da296dcb1e47 // indirect
	github.com/opencontainers/runc v0.0.0-20180125150909-c4e4bb0df2fc
	github.com/opencontainers/runtime-spec v1.0.1 // indirect
	github.com/pborman/uuid v1.2.0
	github.com/pkg/errors v0.8.1
	github.com/sargun/virtual-kubelet v0.9.1-0.20190509064251-57bb80ae5f54 // indirect
	github.com/sirupsen/logrus v1.4.1
	github.com/smartystreets/goconvey v0.0.0-20190330032615-68dc04aab96a // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.3.0
	github.com/ugorji/go v1.1.4 // indirect
	github.com/virtual-kubelet/virtual-kubelet v0.9.1-0.20190509064251-57bb80ae5f54
	github.com/vishvananda/netlink v0.0.0-20180205182215-a2af46a09c21
	github.com/vishvananda/netns v0.0.0-20160430053723-8ba1072b58e0
	github.com/wercker/journalhook v0.0.0-20180428041537-5d0a5ae867b3
	golang.org/x/sync v0.0.0-20190227155943-e225da77a7e6
	golang.org/x/sys v0.0.0-20190403152447-81d4e9dc473e
	golang.org/x/tools v0.0.0-20190328211700-ab21143f2384
	google.golang.org/api v0.3.2 // indirect
	google.golang.org/grpc v1.20.1 // indirect
	gopkg.in/alessio/shellescape.v1 v1.0.0-20170105083845-52074bc9df61
	gopkg.in/ini.v1 v1.42.0 // indirect
	gopkg.in/urfave/cli.v1 v1.20.0
	k8s.io/api v0.0.0-20190503110853-61630f889b3c
	k8s.io/apimachinery v0.0.0-20190503221204-7a17edec881a
	k8s.io/apiserver v0.0.0-20190504023914-7dc4ceb2fd33 // indirect
	k8s.io/client-go v0.0.0-20190425172711-65184652c889
	k8s.io/kubernetes v1.14.1
	k8s.io/utils v0.0.0-20190506122338-8fab8cb257d5 // indirect
)

replace github.com/virtual-kubelet/virtual-kubelet => /Users/sargun/go/src/github.com/virtual-kubelet/virtual-kubelet

replace go.opencensus.io => go.opencensus.io v0.20.2

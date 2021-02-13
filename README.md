# Virtual-Kubelet executor for Titus

[![Build status](https://badge.buildkite.com/378856785cd7805f1efad9b69086205f82ec69ac8ba18e9479.svg)](https://buildkite.com/netflix/titus-executor)
[![Packge Cloud](https://img.shields.io/badge/deb-packagecloud.io-844fec.svg)](https://packagecloud.io/netflix/titus)

Runs [Titus](https://netflix.github.io/titus/) containers using Docker.

## Building
### Prerequisites
You must have Docker 1.13+ installed on your system, and it must be running. The steps to install it can be found [on the docker website](https://docs.docker.com/engine/installation/linux/docker-ce/ubuntu/#set-up-the-repository). Once it is installed, you may have to run the following command, prior to logging out and back in again:
```
gpasswd -a $YOURUSER docker # Fill in $YOURUSER with your user name
```

You must have a Go 1.12 development environment set up. You can find more details on installing Go, [on their website](https://golang.org/doc/install). You must also install the `build-essential` metapackage on Linux.

We recommend setting up a GOPATH, and checking out your code into that GOPATH. For example:

```sh-session
mkdir -p ${HOME}/go
## You add these lines to your .bashrc
export GOPATH=${HOME}/go
export PATH=${GOPATH}/bin:${PATH}
##
```

And then you can check out `github.com/Netflix/titus-executor` to `${GOPATH}/src/github.com/Netflix/titus-executor` -- an easy way to do this is go run `go get -u github.com/Netflix/titus-executor`.

# Initial setup steps
Ensure that your build environment (i.e. VM) has the following commands prior to building:
* make
* gcc

### Building and testing
In order to build titus-executor, check out the project into your `$GOPATH/src/github.com/Netflix`, and run the following command:

```sh-session
sudo -E PATH=${PATH} make builder all
```

This will output a debian file at the path, which you can then install on your system:
`./build/distributions/titus-executor_latest.deb`

To only build the .deb, and not rebuild the builder image:

```sh-session
sudo -E PATH=${PATH} make build
```

#### Building without Docker
If you want to build a dpkg, without Docker, once the code is checked out, you can run the following:

```sh-session
make build-standalone
```

## Linting
Linting is done via the [golangci-lint](https://github.com/golangci/golangci-lint) package, which runs various linters.

To run lint checks:
```sh-session
# Lint all files:
make lint
# Run lint checks inside a docker container:
make validate-docker
```

## Testing
### Local Testing
You should be able to run "local" testing on your system. These are going to be tests that are primarily unit tests, and test for logical correctness, and not for correctness of interaction with system daemons:

```sh-session
make test-local
```

Tests will run locally, according to whatever platform you're on.

### Standalone tests in a Docker container

Requires docker:

```sh-session
make test-standalone

# Disable running tests in parallel and change the test timeout (useful on slower systems):
TEST_FLAGS="-v -parallel 1" TEST_TIMEOUT=10m make test-standalone
# If you're iterating on tests and don't want to build a new executor .deb every time:
./hack/tests-with-dind.sh
```

Tests will run inside a Docker container and run a dedicated docker daemon as docker-in-docker.

AWS specific features (VPC integration, metadata service proxy, GPU, EFS, ...) are disabled during these tests.

## Generated Code
There are places inside of the executor where we've checked in binaries, or prebuilt pieces of code. This may be considered harmful by some, but from the perspective of pragmatism, we have such code in:

In order to generate code you need `go-bindata`, which you can get via:

```sh-session
go get -u github.com/jteeuwen/go-bindata/...
```

### `vpc/bpf`
There are two pieces of generated code:

* `vpc/bpf/filter.o`: This is compiled from `vpc/bpf/filter.c`. We ship this precompiled because it changes infrequently, and it requires LLVM, and the full kernel headers
* `vpc/bpf/filter/filter.go`: This is a go package generated using go-bindata based upon `vpc/bpf/filter.o`

In order to regenerate this data, if you edit `vpc/bpf/filter.c`, you can do so by running:

```sh-session
make -C vpc/bpf/
```

### api/netflix/titus
If you update the dependency `github.com/Netflix/titus-api-definitions/src/main/proto/netflix/titus`, you will need to regenerate the Go proto definitions.

You must first install the protobuf toolchain, and the Go protobuf compiler. More documentation on that can be found [in the protobuf repo](https://github.com/golang/protobuf/blob/master/README.md#installation).

Once you update, and sync the dependency, just run the following:

```sh-session
make clean-proto-defs protogen
```

## Running

### nvidia GPUs

To use with nvidia devices, you must have an OCI runtime installed that supports running OCI prestart hooks, so that the [nvidia-container-runtime-hook](https://github.com/NVIDIA/nvidia-container-runtime) can be run before container start. You'll need to add a container runtime [as per the dockerd documentation](https://docs.docker.com/engine/reference/commandline/dockerd/#docker-runtime-execution-options). The executor looks for a runtime named `oci-add-hooks` by default, but the runtime can be configured via the `titus.executor.nvidiaOciRuntime` config option. You can use the [nvidia-docker](https://github.com/NVIDIA/nvidia-docker) runtime, or the [oci-add-hooks](https://github.com/awslabs/oci-add-hooks) runtime if you're not comfortable running a patched version of runc.

## LICENSE

Copyright (c) 2021 Netflix, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# Mesos executor for Titus

Currently runs titus containers using Docker.

## Building
### Prerequisites
You must have Docker 1.13+ installed on your system, and it must be running. The steps to install it can be found [on the docker website](https://docs.docker.com/engine/installation/linux/docker-ce/ubuntu/#set-up-the-repository). Once it is installed, you may have to run the following command, prior to logging out and back in again:
```
gpasswd -a $YOURUSER docker # Fill in $YOURUSER with your user name
```

You must have a Go 1.11 development environment set up. You can find more details on installing Go, [on their website](https://golang.org/doc/install). You must also install the `build-essential` metapackage on Linux.

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
1. `curl -fsSL https://raw.githubusercontent.com/alecthomas/gometalinter/master/scripts/install.sh | bash -s -- -b $GOPATH/bin v2.0.11`
2. You also need to make sure that your build environment (i.e. VM) has the following commands prior to building:
* make
* gcc
```


### Building and testing
In order to build titus-executor, check out the project into your `$GOPATH/src/github.com/Netflix`, and run the following command:

`sudo -E PATH=${PATH} make builder all`

This will output a debian file at the path, which you can then install on your system:
`./build/distributions/titus-executor_latest.deb`

#### Building without Docker
If you want to build a dpkg, without Docker, once the code is checked out, you can run the following:

```sh-session
make build-standalone
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

## LICENSE

Copyright (c) 2018 Netflix, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

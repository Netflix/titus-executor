# Mesos executor for Titus

Currently runs titus containers using Docker.

## Building
### Prerequisites
You must have Docker 1.13+ installed on your system, and it must be running. The steps to install it can be found [on the docker website](https://docs.docker.com/engine/installation/linux/docker-ce/ubuntu/#set-up-the-repository). Once it is installed, you may have to run the following command, prior to logging out and back in again:
```
gpasswd -a $YOURUSER docker # Fill in $YOURUSER with your user name
```

You must have a Go 1.9+ development environment set up. You can find more details on installing Go, [on their website](https://golang.org/doc/install). You must also install the `build-essential` metapackage. The following commands will install the Go dependencies:

```
# Initial setup steps
go get -u github.com/alecthomas/gometalinter
gometalinter --install
go get -u github.com/kardianos/govendor
```


### Building and testing
In order to build titus-executor, check out the project into your `$GOPATH/src/github.com/Netflix`, and run the following command:

`sudo -E PATH=${PATH} make builder all`

This will output a debian file at the path, which you can then install on your system:
`./build/distributions/titus-executor_latest.deb`

## Standalone tests in a Docker container

Requires docker:

```sh-session
make test-standalone
```

Tests will run inside a Docker container and run a dedicated docker daemon as docker-in-docker.

AWS specific features (VPC integration, metadata service proxy, GPU, EFS, ...) are disabled during these tests.

## Generating Go code based on the agent protobuf definition

```sh-session
make protogen
```

### Force the protobuf definiition to be re-fetched and Go code re-generated

```sh-session
make clean-proto-defs && make protogen
```

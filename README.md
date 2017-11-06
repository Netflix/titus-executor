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

Requires docker and a JVM capable of running gradle:

```sh-session
make protogen
```

This will download a released version of the `titus-api-definitions` package, extract the `agent.proto` file from it
into `./build/lib`, and run the `protoc` compiler (using the gogoprotobuf libraries) in a Docker container to generate
the necessary Go source code into `./api`.

The `agent.proto` file will be only fetched once and cached. Local modifications can be made during dev and Go code
can be re-generated as many times as necessary with `make protogen`.

### Force the protobuf definiition to be re-fetched and Go code re-generated

```sh-session
make clean-proto-defs && make protogen
```

### Using a SNAPSHOT release from the local maven repo

To iterate on a locally modified version of the proto defitions during development:

```sh-session
make clean-proto-defs && make PROTO_SNAPSHOT=true protogen
```

Note that the protobuf definitions will be pulled from a local maven repo in this case (usually found in `~/.m2`), which
requires a `SNAPSHOT` version of the `titus-api-definitions` package being published to the local maven repo, with a
version number higher than the released version in the remote repository.

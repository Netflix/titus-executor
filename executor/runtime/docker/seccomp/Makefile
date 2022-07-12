# Rerun this whenever you change your security profiles

all: seccomp.go test fmt

.PHONY: clean
clean:
	rm *.json seccomp.go

.PHONY: fmt
fmt:
	jsonnetfmt --in-place *.jsonnet *.libsonnet

test: seccomp.go
	go test -v github.com/Netflix/titus-executor/executor/runtime/docker/seccomp

stock.docker.json:
	curl https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json > $@

# seccomp.go is machine-generated, and is a golang representation of the data
# included in these json files
seccomp.go: default.json fuse-container.json allow-perf-syscalls.json
	gobin -run github.com/kevinburke/go-bindata/go-bindata@v3.21.0 -pkg seccomp -o $@ $?

# These JSON files are machine generated from jsonnet files.
# They are not meant to be human-edited
default.json: default.jsonnet stock.docker.json titus.libsonnet
	jsonnet $< > $@

fuse-container.json: fuse-container.jsonnet stock.docker.json titus.libsonnet
	jsonnet $< > $@

allow-perf-syscalls.json: allow-perf-syscalls.jsonnet stock.docker.json titus.libsonnet
	jsonnet $< > $@

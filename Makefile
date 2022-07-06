# Builds the Titus Executor

export

# variables for order-only dependencies
include hack/make/dependencies.mk

# configuration for docker run
include hack/make/docker.mk

SHELL                 := /usr/bin/env bash -eu -o pipefail
LOCAL_DIRS            = $(shell go list ./...)
TEST_FLAGS            ?= -v -parallel 2
TEST_OUTPUT           ?= test.xml
TEST_DOCKER_OUTPUT    ?= test-standalone-docker.xml
GOBIN                 ?= $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))/bin
PATH                  := $(PATH):$(GOBIN)
GOBIN_TOOL            = $(shell which gobin || echo $(GOBIN)/gobin)
GOIMPORT_TOOL		  = $(GOBIN_TOOL) -m -run golang.org/x/tools/cmd/goimports@v0.1.0 -w
GOLANGCI_LINT_TIMEOUT := 2m
ifdef FAST
	GOLANGCI_LINT_ARGS = --fast
endif

SHORT_CIRCUIT_QUITELITE := true

.PHONY: all
all: validate-docker test build

.PHONY: clean
clean:
	rm -rf build/
	rm -f $(TEST_OUTPUT) $(TEST_DOCKER_OUTPUT)

.PHONY: build
build: vpc/service/db/migrations/bindata.go | $(clean) $(builder)
	mkdir -p $(PWD)/build/distributions
	$(DOCKER_RUN) -v $(PWD):$(PWD) -u $(UID):$(GID) -w $(PWD) \
	-e "BUILD_HOST=$(JENKINS_URL)" -e "BUILD_JOB=$(JOB_NAME)" -e BUILD_NUMBER -e BUILD_ID -e ITERATION -e BUILDKITE_BRANCH \
	-e ENABLE_DEV -e GOCACHE=$(PWD)/.cache -e GOPATH=/tmp/gopath \
	titusoss/titus-executor-builder

.PHONY: build-standalone
build-standalone:
	hack/builder/titus-executor-builder.sh

.PHONY: test
test: test-local test-standalone test-misc

TEST_DIRS = $(shell go list -f 'TEST-{{.ImportPath}}' ./...)
.PHONY: $(TEST_DIRS)
$(TEST_DIRS): | $(clean)
	$(eval import_path := $(subst TEST-,,$@))
	CGO_ENABLED=0 go test -short -o test-darwin/$(import_path).test -c $(import_path)
	$(RM) test-darwin/$(import_path).test

.PHONY: build-tests-darwin
build-tests-darwin: $(TEST_DIRS)

.PHONY: cross-linux
cross-linux:
	gox -osarch="linux/amd64" -output="build/bin/{{.OS}}-{{.Arch}}/{{.Dir}}" -verbose ./cmd/...

.PHONY: test-local
test-local: | $(clean)
	CGO_ENABLED=0 go test -short $(TEST_FLAGS) -covermode=count -coverprofile=coverage-local.out -coverpkg=github.com/Netflix/... ./... \
	| tee /dev/stderr > test-local.log

# run standalone tests against the docker container runtime
.PHONY: test-standalone
test-standalone: titus-agent | $(clean) $(builder)
	./hack/tests-with-dind.sh

.PHONY: test-misc
test-misc:
	shellcheck --shell=sh --exclude=SC1008 ./hack/images/titus-sshd/run-titus-sshd
	$(MAKE) -C executor/runtime/docker/seccomp/ test

## Source code

.PHONY: validate
validate: metalinter

.PHONY: validate-docker
validate-docker: | $(builder)
	$(DOCKER_RUN) -v $(PWD):/builds -w /builds titusoss/titus-executor-builder make -j lint

.PHONY: fmt
fmt: $(GOBIN_TOOL)
	$(GOIMPORT_TOOL) $(shell go list -f '{{.Dir}}' ./...)
	$(MAKE) -C executor/runtime/docker/seccomp/ fmt

.PHONY: golangci-lint
golangci-lint: $(GOBIN_TOOL)
	GOOS=linux $(GOBIN_TOOL) -run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.34.1 run --timeout $(GOLANGCI_LINT_TIMEOUT) $(GOLANGCI_LINT_ARGS)

.PHONY: lint
lint: golangci-lint

.PHONY: metalinter
metalinter: lint
	$(warning call the lint target)

## Targets for building binaries directly on linux

.PHONY: tini
tini: build/tini/tini-static
build/tini/tini-static: tini/src/*
	rm -rf build/tini && mkdir -p build/tini
	cd build/tini && cmake -DCMAKE_BUILD_TYPE=Release ../../tini && make V=1
.PHONY: tini-install-locally
tini-install-locally: build/tini/tini-static
	sudo rsync build/tini/tini-static /apps/titus-executor/bin/tini-static

## Support docker images

.PHONY: builder
builder:
	@echo '---> Building titusoss/titus-executor-builder'
	$(DOCKER) build -t titusoss/titus-executor-builder hack/builder

.PHONY: push-builder
push-builder: builder
	$(DOCKER) push titusoss/titus-executor-builder

.PHONY: titus-agent
titus-agent: build
	@echo '---> Building Titus Agent Docker-in-Docker image'
	@$(DOCKER_BUILD) -t titusoss/titus-agent -f hack/agent/Dockerfile .

.PHONY: push-titus-agent
push-titus-agent: titus-agent
	$(DOCKER) push titusoss/titus-agent

## Protobuf and source code generation

PROTO_DIR     = vendor/github.com/Netflix/titus-api-definitions/src/main/proto
PROTOS        := $(PROTO_DIR)/netflix/titus/titus_base.proto $(PROTO_DIR)/netflix/titus/titus_agent_api.proto $(PROTO_DIR)/netflix/titus/agent.proto $(PROTO_DIR)/netflix/titus/titus_vpc_api.proto $(PROTO_DIR)/netflix/titus/titus_job_api.proto $(PROTO_DIR)/netflix/titus/titus_volumes.proto $(PROTO_DIR)/netflix/titus/titus_containers.proto
PROTOS_OUT	  := $(patsubst $(PROTO_DIR)/%.proto,api/%.pb.go,$(PROTOS))
GRPC_OUT	  := $(patsubst $(PROTO_DIR)/%.proto,api/%_grpc.pb.go,$(PROTOS))
PROTO_MAP	:= Mnetflix/titus/titus_base.proto=github.com/Netflix/titus-executor/api/netflix/titus,Mnetflix/titus/titus_job_api.proto=github.com/Netflix/titus-executor/api/netflix/titus,Mnetflix/titus/titus_agent_api.proto=github.com/Netflix/titus-executor/api/netflix/titus,Mnetflix/titus/agent.proto=github.com/Netflix/titus-executor/api/netflix/titus,Mnetflix/titus/titus_vpc_api.proto=github.com/Netflix/titus-executor/api/netflix/titus,Mnetflix/titus/titus_volumes.proto=github.com/Netflix/titus-executor/api/netflix/titus,Mnetflix/titus/titus_containers.proto=github.com/Netflix/titus-executor/api/netflix/titus
.PHONY: protogen
protogen: $(PROTOS_OUT) vpc/api/vpc.pb.go metadataserver/api/iam.pb.go | $(clean) $(clean-proto-defs)

vendor: vendor/modules.txt
vendor/modules.txt: go.mod
	go mod vendor

$(PROTOS): vendor
$(GRPC_OUT) $(PROTOS_OUT): $(PROTOS) $(GOBIN_TOOL) vendor | $(clean) $(clean-proto-defs)
	mkdir -p api/netflix/titus
	$(eval PROTO := $(patsubst api/%.pb.go,$(PROTO_DIR)/%.proto,$@))
	protoc \
		--plugin=protoc-gen-titusgrpc=$(shell $(GOBIN_TOOL) -p google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1) \
		--plugin=protoc-gen-titusgo=$(shell $(GOBIN_TOOL) -p google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1) \
		-I$(PROTO_DIR)/ \
		--titusgo_out=api/ \
		--titusgrpc_out=api/ \
		--titusgo_opt=$(PROTO_MAP) \
		--titusgrpc_opt=$(PROTO_MAP) \
		--titusgo_opt=module=github.com/Netflix/titus-executor/api \
		--titusgrpc_opt=module=github.com/Netflix/titus-executor/api \
		$(patsubst api/%.pb.go,$(PROTO_DIR)/%.proto,$@)
	$(GOIMPORT_TOOL) $@

## TODO: Use git wildcard functionality to "automatically"
vpc/api/vpc_grpc.pb.go vpc/api/vpc.pb.go: vpc/proto/vpc.proto $(GOBIN_TOOL) vendor | $(clean) $(clean-proto-defs)
	mkdir -p vpc/api
	protoc \
		--plugin=protoc-gen-titusgrpc=$(shell $(GOBIN_TOOL) -p google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1) \
		--plugin=protoc-gen-titusgo=$(shell $(GOBIN_TOOL) -p google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1) \
		--titusgo_out=vpc/api/ \
		--titusgrpc_out=vpc/api/ \
		--titusgo_opt=module=github.com/Netflix/titus-executor/vpc/api \
		--titusgrpc_opt=module=github.com/Netflix/titus-executor/vpc/api \
		-I$(PROTO_DIR) \
		-Ivpc/proto \
		--titusgo_opt=$(PROTO_MAP) \
		--titusgrpc_opt=$(PROTO_MAP) \
		vpc/proto/vpc.proto
	$(GOIMPORT_TOOL) $@

metadataserver/api/iam_grpc.pb.go metadataserver/api/iam.pb.go: metadataserver/proto/iam.proto $(GOBIN_TOOL) vendor | $(clean) $(clean-proto-defs)
	mkdir -p metadataserver/api
	protoc \
		--plugin=protoc-gen-titusgrpc=$(shell $(GOBIN_TOOL) -p google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1) \
		--plugin=protoc-gen-titusgo=$(shell $(GOBIN_TOOL) -p google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1) \
		--titusgo_out=metadataserver/api/ \
		--titusgrpc_out=metadataserver/api/ \
		--titusgo_opt=$(PROTO_MAP) \
		--titusgrpc_opt=$(PROTO_MAP) \
		--titusgo_opt=module=github.com/Netflix/titus-executor/metadataserver/api \
		--titusgrpc_opt=module=github.com/Netflix/titus-executor/metadataserver/api \
		metadataserver/proto/iam.proto
	$(GOIMPORT_TOOL) $@

.PHONY: clean-proto-defs
clean-proto-defs: | $(clean)
	rm -rf api/netflix/titus
	rm -rf vpc/api

$(GOBIN_TOOL):
	go get github.com/myitcv/gobin
	go install github.com/myitcv/gobin

vpc/service/db/migrations/bindata.go: vpc/service/db/migrations/generate.go vpc/service/db/migrations/*.sql
	go generate ./vpc/service/db/migrations/
	make fmt

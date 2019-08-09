# Builds the Titus Executor

export

# variables for order-only dependencies
include hack/make/dependencies.mk

# configuration for docker run
include hack/make/docker.mk

SHELL                 := /usr/bin/env bash -eu -o pipefail
LOCAL_DIRS            = $(shell go list ./...)
TEST_FLAGS            ?= -v -parallel 32
TEST_OUTPUT           ?= test.xml
TEST_DOCKER_OUTPUT    ?= test-standalone-docker.xml
GOBIN                 ?= $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))/bin
PATH                  := $(PATH):$(GOBIN)
GOBIN_TOOL            = $(shell which gobin || echo $(GOBIN)/gobin)
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

.PHONY: tini/src
tini/src:
	git submodule update --init --recursive

.PHONY: build
build: tini/src | $(clean) $(builder)
	mkdir -p $(PWD)/build/distributions
	$(DOCKER_RUN) -v $(PWD):$(PWD) -u $(UID):$(GID) -w $(PWD) \
	-e "BUILD_HOST=$(JENKINS_URL)" -e "BUILD_JOB=$(JOB_NAME)" -e BUILD_NUMBER -e BUILD_ID -e ITERATION -e BUILDKITE_BRANCH \
	-e ENABLE_DEV -e GOCACHE=$(PWD)/.cache \
	titusoss/titus-executor-builder

.PHONY: build-standalone
build-standalone: tini/src
	hack/builder/titus-executor-builder.sh

.PHONY: test
test: test-local test-standalone

TEST_DIRS = $(shell go list -f 'TEST-{{.ImportPath}}' ./...)
.PHONY: $(TEST_DIRS)
$(TEST_DIRS): | $(clean)
	$(eval import_path := $(subst TEST-,,$@))
	go test -o test-darwin/$(import_path).test -c $(import_path)
	$(RM) test-darwin/$(import_path).test

.PHONY: build-tests-darwin
build-tests-darwin: $(TEST_DIRS)

.PHONY: cross-linux
cross-linux:
	gox -osarch="linux/amd64" -output="build/bin/{{.OS}}-{{.Arch}}/{{.Dir}}" -verbose ./cmd/...

.PHONY: test-local
test-local: | $(clean)
	go test $(TEST_FLAGS) -covermode=count -coverprofile=coverage-local.out -coverpkg=github.com/Netflix/... ./... \
	| tee /dev/stderr > test-local.log

# run standalone tests against the docker container runtime
.PHONY: test-standalone
test-standalone: titus-agent | $(clean) $(builder)
	./hack/tests-with-dind.sh


## Source code

.PHONY: validate
validate: metalinter

.PHONY: validate-docker
validate-docker: | $(builder)
	$(DOCKER_RUN) -v $(PWD):/builds -w /builds titusoss/titus-executor-builder make -j validate

.PHONY: fmt
fmt: $(GOBIN_TOOL)
	$(GOBIN_TOOL) -m -run golang.org/x/tools/cmd/goimports -w $(shell go list -f '{{.Dir}}' ./...)

.PHONY: golangci-lint
golangci-lint: $(GOBIN_TOOL)
	$(GOBIN_TOOL) -m -run github.com/golangci/golangci-lint/cmd/golangci-lint run $(GOLANGCI_LINT_ARGS)

.PHONY: lint
lint: golangci-lint

.PHONY: metalinter
metalinter: lint
	$(warning call the lint target)

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
PROTOS        := $(PROTO_DIR)/netflix/titus/titus_base.proto $(PROTO_DIR)/netflix/titus/titus_agent_api.proto $(PROTO_DIR)/netflix/titus/agent.proto $(PROTO_DIR)/netflix/titus/titus_vpc_api.proto $(PROTO_DIR)/netflix/titus/titus_job_api.proto
PROTO_MAP     := Mnetflix/titus/titus_base.proto=github.com/Netflix/titus-executor/api/netflix/titus
.PHONY: protogen
protogen: $(GOBIN_TOOL) | $(clean) $(clean-proto-defs)
	mkdir -p api
	protoc --plugin=protoc-gen-titusgo=$(shell $(GOBIN_TOOL) -m -p github.com/golang/protobuf/protoc-gen-go) -I$(PROTO_DIR)/ -Ivpc/proto --titusgo_out=plugins=grpc:api/ $(PROTOS)
	mkdir -p vpc/api
	protoc --plugin=protoc-gen-titusgo=$(shell $(GOBIN_TOOL) -m -p github.com/golang/protobuf/protoc-gen-go) -I$(PROTO_DIR)/ -Ivpc/proto --titusgo_out=plugins=grpc,$(PROTO_MAP):vpc/api/ vpc/proto/vpc.proto

.PHONY: clean-proto-defs
clean-proto-defs: | $(clean)
	rm -rf api/netflix/titus
	rm -rf vpc/api

$(GOBIN_TOOL):
	go get github.com/myitcv/gobin
	go install github.com/myitcv/gobin

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
	-e ENABLE_DEV -e GOCACHE=$(PWD)/.cache \
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

## Source code

.PHONY: validate
validate: metalinter

.PHONY: validate-docker
validate-docker: | $(builder)
	$(DOCKER_RUN) -v $(PWD):/builds -w /builds titusoss/titus-executor-builder make -j lint

.PHONY: fmt
fmt: $(GOBIN_TOOL)
	$(GOIMPORT_TOOL) $(shell go list -f '{{.Dir}}' ./...)

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
PROTOS        := $(PROTO_DIR)/netflix/titus/titus_base.proto $(PROTO_DIR)/netflix/titus/titus_agent_api.proto $(PROTO_DIR)/netflix/titus/agent.proto $(PROTO_DIR)/netflix/titus/titus_vpc_api.proto $(PROTO_DIR)/netflix/titus/titus_job_api.proto
.PHONY: protogen
protogen: vpc/api/vpc.pb.go metadataserver/api/iam.pb.go | $(clean) $(clean-proto-defs)
	mkdir -p api/netflix/titus
	protoc --proto_path=$(PROTO_DIR) \
		--go_opt=module=netflix/titus \
		--go_opt=Mnetflix/titus/titus_base.proto=netflix/titus \
		--go_opt=Mnetflix/titus/agent.proto=netflix/titus  \
		--go_opt=Mnetflix/titus/agent_api.proto=netflix/titus  \
		--go_opt=Mnetflix/titus/titus_agent_api.proto=netflix/titus  \
		--go_opt=Mnetflix/titus/titus_vpc_api.proto=netflix/titus  \
		--go_opt=Mnetflix/titus/titus_job_api.proto=netflix/titus  \
		--go_out=api/netflix/titus $(PROTOS)
	protoc --proto_path=$(PROTO_DIR) \
		--go-grpc_opt=module=netflix/titus \
		--go-grpc_opt=Mnetflix/titus/titus_base.proto=netflix/titus \
		--go-grpc_opt=Mnetflix/titus/agent.proto=netflix/titus  \
		--go-grpc_opt=Mnetflix/titus/agent_api.proto=netflix/titus  \
		--go-grpc_opt=Mnetflix/titus/titus_agent_api.proto=netflix/titus  \
		--go-grpc_opt=Mnetflix/titus/titus_vpc_api.proto=netflix/titus  \
		--go-grpc_opt=Mnetflix/titus/titus_job_api.proto=netflix/titus  \
		--go-grpc_out=require_unimplemented_servers=false:api/netflix/titus $(PROTOS)

vpc/api/vpc.pb.go: vpc/proto/vpc.proto $(GOBIN_TOOL) vendor | $(clean) $(clean-proto-defs)
	mkdir -p vpc/api
	protoc --proto_path=$(PROTO_DIR) --proto_path=vpc/proto \
		--go_opt=module=vpc/api/vpcapi \
		--go_opt=Mnetflix/titus/titus_base.proto=github.com/Netflix/titus-executor/api/netflix/titus \
		--go_opt=Mvpc.proto=vpc/api/vpcapi  \
		--go_out=vpc/api vpc/proto/vpc.proto
	protoc --proto_path=$(PROTO_DIR) --proto_path=vpc/proto \
		--go-grpc_opt=module=vpc/api/vpcapi \
		--go-grpc_opt=Mnetflix/titus/titus_base.proto=github.com/Netflix/titus-executor/api/netflix/titus \
		--go-grpc_opt=Mvpc.proto=vpc/api/vpcapi  \
		--go-grpc_out=require_unimplemented_servers=false:vpc/api vpc/proto/vpc.proto

metadataserver/api/iam.pb.go: metadataserver/proto/iam.proto $(GOBIN_TOOL) vendor | $(clean) $(clean-proto-defs)
	mkdir -p metadataserver/api
	protoc --proto_path=$(PROTO_DIR) --proto_path=metadataserver/proto \
		--go_opt=module=metadataserver/api/iamapi \
		--go_opt=Mnetflix/titus/titus_base.proto=github.com/Netflix/titus-executor/api/netflix/titus \
		--go_opt=Miam.proto=metadataserver/api/iamapi \
		--go_out=metadataserver/api/ metadataserver/proto/iam.proto
	protoc --proto_path=$(PROTO_DIR) --proto_path=metadataserver/proto \
		--go-grpc_opt=module=metadataserver/api/iamapi \
		--go-grpc_opt=Mnetflix/titus/titus_base.proto=github.com/Netflix/titus-executor/api/netflix/titus \
		--go-grpc_opt=Miam.proto=metadataserver/api/iamapi  \
		--go-grpc_out=require_unimplemented_servers=false:metadataserver/api/ metadataserver/proto/iam.proto

vendor: vendor/modules.txt
vendor/modules.txt: go.mod
	go mod vendor



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

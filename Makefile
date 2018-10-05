# Builds the Titus Executor

export

# variables for order-only dependencies
include hack/make/dependencies.mk

# configuration for docker run
include hack/make/docker.mk

# configuration for gometalinter
include hack/make/lint.mk

SHELL                 := /usr/bin/env bash -eu -o pipefail
GO_PKG                := github.com/Netflix/titus-executor
LOCAL_DIRS            = $(shell govendor list -p -no-status +local)
TEST_FLAGS            ?= -v -parallel 32
TEST_OUTPUT           ?= test.xml
TEST_DOCKER_OUTPUT    ?= test-standalone-docker.xml
GOIMPORTS             := $(GOPATH)/bin/goimports
GOVENDOR              := $(GOPATH)/bin/govendor
PROTOC_GEN_GO         := $(GOPATH)/bin/protoc-gen-go

SHORT_CIRCUIT_QUITELITE := true

.PHONY: all
all: validate-docker test build

.PHONY: clean
clean:
	go clean || true
	rm -rf build/
	rm -f $(TEST_OUTPUT) $(TEST_DOCKER_OUTPUT)

.PHONY: tini/src
tini/src:
	git submodule update --init --recursive

.PHONY: build
build: tini/src | $(clean) $(builder)
	mkdir -p $(PWD)/build/distributions
	$(DOCKER_RUN) -v $(PWD):$(PWD) -u $(UID):$(GID) \
	-e "BUILD_HOST=$(JENKINS_URL)" -e "BUILD_JOB=$(JOB_NAME)" -e BUILD_NUMBER -e BUILD_ID -e ITERATION -e BUILDKITE_BRANCH \
	-e ENABLE_DEV -e GOPATH \
	titusoss/titus-executor-builder

.PHONY: build-standalone
build-standalone: tini/src
	hack/builder/titus-executor-builder.sh

.PHONY: test
test: test-local test-standalone

.PHONY: build-tests-darwin
build-tests-darwin: $(GOVENDOR) | $(clean)
	$(eval TESTS_BUILD_DIR:=$(shell mktemp -d -t "build-tests.XXXXXX"))
	for p in $$(govendor list -no-status +local); do \
	  GOOS="darwin" govendor test -c $$p -o $(TESTS_BUILD_DIR)/$$p.test; \
	done
	$(RM) -r "$(TESTS_BUILD_DIR)"

.PHONY: test-local
test-local: $(GOVENDOR) | $(clean)
	$(GOVENDOR) test $(TEST_FLAGS) -covermode=count -coverprofile=coverage-local.out -coverpkg=github.com/Netflix/... +local \
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
	$(DOCKER_RUN) -v $(PWD):$(PWD) -e GOPATH -w $(PWD) titusoss/titus-executor-builder make -j validate

.PHONY: fmt
fmt: $(GOIMPORTS) $(GOVENDOR)
	govendor fmt +local
	$(GOIMPORTS) -w $(LOCAL_DIRS)

.PHONY: metalinter
metalinter: testdeps
ifdef FAST
	gometalinter $(GOMETALINTER_OPTS) $(shell git diff origin/master --name-only --diff-filter=AM | grep 'go$$' | egrep -v '(^|/)vendor/' | /usr/bin/xargs -L1 dirname|sort|uniq) \
	| tee $(LINTER_OUTPUT)
else
	gometalinter $(GOMETALINTER_OPTS) $(LOCAL_DIRS) | tee $(LINTER_OUTPUT)
endif


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

PROTOS := vendor/github.com/Netflix/titus-api-definitions/src/main/proto/netflix/titus/titus_base.proto vendor/github.com/Netflix/titus-api-definitions/src/main/proto/netflix/titus/titus_agent_api.proto vendor/github.com/Netflix/titus-api-definitions/src/main/proto/netflix/titus/agent.proto
.PHONY: protogen
protogen: $(PROTOS) $(PROTOC_GEN_GO) | $(clean) $(clean-proto-defs)
	mkdir -p api
	protoc -Ivendor/github.com/Netflix/titus-api-definitions/src/main/proto/ --go_out=api/ $(PROTOS)

.PHONY: clean-proto-defs
clean-proto-defs: | $(clean)
	rm -rf api/netflix/titus


## Binary dependencies
$(PROTOC_GEN_GO): vendor/vendor.json vendor/github.com/golang/protobuf/protoc-gen-go
	govendor install ./vendor/github.com/golang/protobuf/protoc-gen-go

$(GOIMPORTS):
	go get golang.org/x/tools/cmd/goimports

$(GOVENDOR):
	go get github.com/kardianos/govendor

.PHONY: testdeps
testdeps: $(GOVENDOR)
	$(GOVENDOR) install +local
	# Fail if gometalinter is not present in PATH:
	which gometalinter

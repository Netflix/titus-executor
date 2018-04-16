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
test: test-local test-standalone build-tests-darwin

.PHONY: build-tests-darwin
build-tests-darwin: govendor | $(clean)
	$(eval TESTS_BUILD_DIR:=$(shell mktemp -d -t "build-tests.XXXXXX"))
	for p in $$(govendor list -no-status +local); do \
	  GOOS="darwin" govendor test -c $$p -o $(TESTS_BUILD_DIR)/$$p.test; \
	done
	$(RM) -r "$(TESTS_BUILD_DIR)"

.PHONY: test-local
test-local: govendor go-junit-report | $(clean)
	govendor test $(TEST_FLAGS) +local \
	| tee /dev/stderr \
	| tee test-local.log \
	| go-junit-report > $(TEST_OUTPUT)

# run standalone tests against the docker container runtime
.PHONY: test-standalone
test-standalone: titus-agent go-junit-report | $(clean) $(builder)
	./hack/tests-with-dind.sh


## Source code

.PHONY: validate
validate: metalinter

.PHONY: validate-docker
validate-docker: | $(builder)
	$(DOCKER_RUN) -v $(PWD):$(PWD) -e GOPATH -w $(PWD) titusoss/titus-executor-builder make -j validate

.PHONY: fmt
fmt: goimports govendor
	govendor fmt +local
	goimports -w $(LOCAL_DIRS)

.PHONY: metalinter
metalinter: testdeps
ifdef FAST
	$(GOMETALINTER) $(shell git diff origin/master --name-only --diff-filter=AM | grep 'go$$' | egrep -v '(^|/)vendor/' | /usr/bin/xargs -L1 dirname|sort|uniq) \
	| tee $(LINTER_OUTPUT)
else
	$(GOMETALINTER) $(LOCAL_DIRS) | tee $(LINTER_OUTPUT)
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
protogen:  $(PROTOS) | $(clean) $(clean_proto_defs)
	mkdir -p api
	protoc -Ivendor/github.com/Netflix/titus-api-definitions/src/main/proto/ --go_out=api/ $(PROTOS)

.PHONY: clean-proto-defs
clean-proto-defs: | $(clean)
	rm -rf api/netflix/titus


## Binary dependencies

.PHONY: goimports
goimports:
	go get golang.org/x/tools/cmd/goimports

.PHONY: govendor
govendor:
	go get github.com/kardianos/govendor

.PHONY: gometalinter
gometalinter:
	go get github.com/alecthomas/gometalinter

.PHONY: testdeps
testdeps: govendor gometalinter
	govendor install +local

.PHONY: go-junit-report
go-junit-report:
	go get github.com/jstemmer/go-junit-report

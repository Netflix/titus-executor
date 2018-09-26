LINTER_OUTPUT         ?= checkstyle-result.xml

NPROCS := 1
OS     := $(shell uname -s)
ifeq ($(OS), Linux)
# There are two tests that should be running in the background - Docker, and Rkt
NPROCS := $(shell nproc --ignore=2)
endif

ifeq ($(JOB_NAME),)
JENKINS	:= false
else
JENKINS	:= true
endif

ifeq ($(JENKINS),true)
CHECKSTYLE := --checkstyle
else
CHECKSTYLE :=
endif

GOMETALINTER_OPTS := --vendor --tests --vendored-linters $(CHECKSTYLE) --disable=maligned --disable=gotype --enable=unused --enable=goimports --enable=gofmt \
    --concurrency=$(NPROCS) --deadline=600s \
    --exclude=api/netflix/titus \
    --exclude=vpc/bpf/filter \
    --exclude=executor/runtime/docker/seccomp \
    --exclude=/usr/local/go/src

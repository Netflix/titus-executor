DOCKER             := $(shell command -v docker 2>/dev/null)
ifdef DOCKER
UID                ?= $(shell id -u)
GID                ?= $(shell id -g)
DOCKER_RUN_FLAGS   ?= --rm --init -t -e DEBUG=$(DEBUG) -e FAST=$(FAST)
DOCKER_RUN         ?= $(DOCKER) run $(DOCKER_RUN_FLAGS)
DOCKER_BUILD_FLAGS ?= -q
DOCKER_BUILD       ?= $(DOCKER) build $(DOCKER_BUILD_FLAGS)
endif


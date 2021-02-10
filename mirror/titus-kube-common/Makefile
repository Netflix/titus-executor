# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

GOBIN_TOOL := $(shell which gobin || echo $(GOBIN)/gobin)

# Run go fmt against code
.PHONY: fmt
fmt: $(GOBIN_TOOL)
	$(GOBIN_TOOL) -m -run golang.org/x/tools/cmd/goimports -w $(shell go list -f '{{.Dir}}' ./...)

# Run lint against code
.PHONY: lint
lint: $(GOBIN_TOOL)
	$(GOBIN_TOOL) -m -run github.com/golangci/golangci-lint/cmd/golangci-lint run --verbose

# Run tests
.PHONY: test
test:
	go test ./... -coverprofile cover.out

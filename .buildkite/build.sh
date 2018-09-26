#!/usr/bin/env bash
set -uex -o pipefail

log() {
    echo -e "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $1" >&2
}

# This should clean the path
mkdir -p ${BUILDKITE_BUILD_CHECKOUT_PATH}/src/github.com/Netflix/titus-executor/

shopt -s dotglob
mv ${BUILDKITE_BUILD_CHECKOUT_PATH}/* ${BUILDKITE_BUILD_CHECKOUT_PATH}/src/github.com/Netflix/titus-executor/ || true

export GOPATH="${BUILDKITE_BUILD_CHECKOUT_PATH}"
export PATH="/usr/local/go/bin:${GOPATH}/bin:${PATH}"

cd ${GOPATH}/src/github.com/Netflix/titus-executor

log "Installing go dependencies"

go get -u github.com/kardianos/govendor
go get -u github.com/wadey/gocovmerge
go get -u github.com/mattn/goveralls

log "Building executor"

make clean
make --output-sync -j16 builder all 2>&1 | tee build.log

log "Running code coverage"

bash <(curl -s https://codecov.io/bash)
gocovmerge coverage-local.out coverage-standalone.out > coverage-combined.out
goveralls -repotoken ${COVERALLS_TOKEN} -coverprofile=coverage-combined.out

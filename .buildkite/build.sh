#!/usr/bin/env bash
set -uex -o pipefail

# This should clean the path
mkdir -p ${BUILDKITE_BUILD_CHECKOUT_PATH}/src/github.com/Netflix/titus-executor/

shopt -s dotglob
mv ${BUILDKITE_BUILD_CHECKOUT_PATH}/* ${BUILDKITE_BUILD_CHECKOUT_PATH}/src/github.com/Netflix/titus-executor/ || true

export GOPATH="${BUILDKITE_BUILD_CHECKOUT_PATH}"
export PATH="/usr/local/go/bin:${GOPATH}/bin:${PATH}"

cd ${GOPATH}/src/github.com/Netflix/titus-executor

go get -u github.com/alecthomas/gometalinter
gometalinter --install
go get -u github.com/kardianos/govendor
go get -u github.com/wadey/gocovmerge
go get -u github.com/mattn/goveralls


make clean
make --output-sync -j16 builder all 2>&1 | tee build.log

bash <(curl -s https://codecov.io/bash)
gocovmerge coverage-local.out coverage-standalone.out > coverage-combined.out
goveralls -repotoken ${COVERALLS_TOKEN} -coverprofile=coverage-combined.out

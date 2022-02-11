#!/usr/bin/env bash
set -ue -o pipefail

log() {
    echo -e "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $1" >&2
}

apt-get -y install shellcheck libseccomp-dev

GO_VERSION=1.13.14
GO_INSTALL_DIR=${HOME}/go_installs/${GO_VERSION}
if [[ ! -d ${GO_INSTALL_DIR}/go ]]; then
    mkdir -p ${GO_INSTALL_DIR}
    curl -Sfl https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz |tar -xz -C ${GO_INSTALL_DIR}
fi
export GOPATH="${HOME}/go"
export PATH="${GO_INSTALL_DIR}/go/bin:${GOPATH}/bin:${PATH}"
export TEST_FLAGS="-v -parallel 1"

# The buildkite agent redacts secrest in the build log, but not on artifacts.
# There "shouldn't" be any sensitive secrets in the build log anyway, except for
# the docker password. The reason we have a docker password in the build output
# is because docker changed their policy to *require* a password on docker pulls
# (or else face severe rate limiting), so this is the one password we try to
# not leak.
redact_secrets() {
  sed "s/$DOCKER_PASSWORD/[REDACTED]/"
}

log "Building executor"

make clean
make --output-sync -j16 builder all 2>&1 | redact_secrets | tee build.log



#!/bin/bash

set -eu -o pipefail

## Runs integration tests against a docker daemon dedicated to them:
#  - the docker daemon runs as docker-in-docker (dind) in background
#  - systemd, dbus and all other titus-executor dependencies are available where the docker daemon runs
#    ... technically, this runs docker-on-systemd-in-docker
#  - tests run against the docker daemon above
#  - this script tries to automatically teardown the systemd container running in background
#
# Environment variables that this script pays attention to:
# - BUILD_ID: Jenkins build ID
# - DEBUG: Run the agent in debug mode?
# - GO_PKG: Can be used to override the working dir under GOPATH
# - JOB_NAME: Jenkins job name
# - TEST_TIMEOUT: timeout for `go test`
# - TEST_FLAGS: flags passed to `go test`

# portable uuidgen
random_uuid=$(od -N 16 -x /dev/urandom | head -1 | awk '{OFS="-"; print $2$3,$4,$5,$6,$7$8$9}')

if [[ -n "${JOB_NAME:-}" && -n "${BUILD_ID:-}" ]]; then
    # we are on Jenkins, tag containers with JOB.ID so they can be tied to specific job runs
    ci_job_id="${JOB_NAME}.${BUILD_ID}"
fi

run_id="${ci_job_id:-$random_uuid}"

log() {
    echo -e "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $1" >&2
}

log "## Titus Integration tests, run ID: $run_id"

# run a dedicated docker daemon (with a custom init-binary) for these tests

titus_agent_name="titus-agent-${run_id}"

terminate_titus_docker() {
    log "## Titus Integration tests ended, terminating the docker container"
    docker exec "$titus_agent_name" journalctl > journald-standalone.log || true
    docker exec "$titus_agent_name" journalctl -ojson > journald-standalone.json || true
    log "Stopping container: $titus_agent_name"
    docker stop "$titus_agent_name" 2>/dev/null || true
    log "Container stopped (rc: $?)"
}

trap terminate_titus_docker EXIT

debug=${DEBUG:-false}
metatron_cert_mnt=""
if [[ $(uname) == "Darwin" ]]; then
  metatron_cert_mnt="-v ${HOME}/.metatron:/mnt/metatron"
fi

log "Running a docker daemon named $titus_agent_name"
docker run --privileged --security-opt seccomp=unconfined \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v ${GOPATH}:${GOPATH} \
  -v ~/.docker/config.json:/root/.docker/config.json \
  -v ${PWD}:${PWD} \
  ${metatron_cert_mnt} \
  -w ${PWD} \
  -e BUMP_TINI_SCHED_PRIORITY=false \
  -e DEBUG=${debug} \
  -e SHORT_CIRCUIT_QUITELITE=true \
  -e GOPATH=${GOPATH} \
  --label "$run_id" \
  --rm --name "$titus_agent_name" \
  -d titusoss/titus-agent

log "Copying test metatron certs to their correct location"
docker exec "$titus_agent_name" ${PWD}/hack/agent/certs/setup-metatron-certs.sh

log "Running integration tests against the $titus_agent_name daemon"
# --privileged is needed here since we are reading FDs from a unix socket
docker exec --privileged -e DEBUG=${debug} -e SHORT_CIRCUIT_QUITELITE=true -e GOPATH=${GOPATH} "$titus_agent_name" \
  go test -timeout ${TEST_TIMEOUT:-20m} ${TEST_FLAGS:-} \
    -covermode=count -coverprofile=coverage-standalone.out \
    -coverpkg=github.com/Netflix/... ./executor/standalone/... -standalone=true 2>&1 | tee test-standalone.log

log "Integration tests complete (rc: $?)"

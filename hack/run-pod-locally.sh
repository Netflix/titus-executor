#!/bin/bash
set -eu -o pipefail
POD_TASK_ID=$(jq -r .metadata.name pod.json)
run_id=$(od -N 16 -x /dev/urandom | head -1 | awk '{OFS="-"; print $2$3,$4,$5,$6,$7$8$9}')
log() {
    echo -e "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $1" >&2
}

docker_container_name="titus-standalone-${run_id}"
terminate_titus_docker() {
    log "## Titus standalone run exited. Terminating docker container"
    docker logs $POD_TASK_ID || true
    docker exec "$docker_container_name" journalctl > titus-standalone.log || true
    log "## Dumpped logs to 'titus-standalone.log'"
    docker logs -f $docker_container_name &
    log "Stopping container: $docker_container_name"
    docker stop "$docker_container_name" 2>/dev/null || true
    log "Container stopped (rc: $?)"
}

trap terminate_titus_docker EXIT

if ! [[ -f "${PWD}/pod.json" ]]; then
  echo "This script requires ${PWD}/pod.json to exist, please run from the root directory"
  exit 1
fi

log "Running a docker daemon named $docker_container_name"
docker stop "/$POD_TASK_ID" || true
docker rm "/$POD_TASK_ID" || true
docker run -ti --privileged --security-opt seccomp=unconfined -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -w / -v ${PWD}:/work \
  -v ${PWD}/pod.json:/etc/titus-executor/pod.json \
  -v ${PWD}/build/bin/linux-amd64/:/apps/titus-executor/bin/:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:rw \
  -e DOCKER_REGISTRY="registry.us-east-1.streamingtest.titus.netflix.net:7002" \
  -e LOGVIEWER_SERVICE_IMAGE="/baseos/nflx-adminlogs@sha256:fe27edfe317163b59e3afaad9a0b5e93e4d731b03bf79650abb4490b8a0fece6" \
  -e SSHD_SERVICE_IMAGE="/titusoss/titus-sshd@sha256:6f6f89250771a50e13d5a3559712defc256c37b144ca22e46c69f35f06d848a0" \
  -e METATRON_SERVICE_IMAGE="/ps/titus-metatron-identity" \
  -e PROXYD_SERVICE_IMAGE="/ipc/proxyd-rootless-candidate@sha256:9d5e5292015856b60cfcca51024cdceba1b07f9fe952b96ccac4b741aab43708" \
  -e ABMETRIX_SERVICE_IMAGE="/baseos/nflx-abmetrix-titus@sha256:0b01b2d74b9b62c7ad85007da0491d40c1f80e5812676667bedcade2448f24e3" \
  -e TITUS_EXECUTOR_TINI_PATH="${PWD}/build/bin/linux-amd64/tini-static" \
  --rm --name "$docker_container_name" \
  -d \
  -e SHORT_CIRCUIT_QUITELITE=true --label "$run_id" titusoss/titus-agent

log "Copying test metatron certs to their correct location"
docker exec "$docker_container_name" /metatron/certificates/setup-metatron-certs.sh

if [[ -e ${PWD}/build/bin/linux-amd64/tini-static ]]; then
  log "Copying the linux tini binary out for use"
  docker cp "$docker_container_name":/apps/titus-executor/bin/tini-static ${PWD}/build/bin/linux-amd64/tini-static
fi

log "Running titus-standalone in $docker_container_name"
docker exec "$docker_container_name" /apps/titus-executor/bin/titus-standalone \
   --log-level=debug \
   -pod /etc/titus-executor/pod.json || true

log "press enter to finish"
read foo

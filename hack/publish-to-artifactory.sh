#!/bin/bash

set -uex -o pipefail

# This assumes a symlink called titus-executor_latest.deb exists and points to the file generated
# by the latest build
pkg="$(readlink build/distributions/titus-executor_latest.deb)"
if [[ -z "${pkg// }" ]]; then
    echo "FAIL: Build produced no deb packages" >&2
    exit 1
fi

newt --app-type adhoc-debian-publisher publish \
     --repo="${DEBIAN_REPO:-titus-debian-local}" \
     --distribution=nflx \
     --component=main \
     --architecture=amd64 "build/distributions/$pkg"


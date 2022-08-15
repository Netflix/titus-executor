#!/bin/bash -uex
set -o pipefail

work="$(mktemp -d)"

function cleanup_work() {
    rm -rf "$work"
}

trap cleanup_work TERM EXIT

cd api/netflix/titus/

git -C "$work" clone --depth=1 ssh://git@stash.corp.netflix.com:7999/tn/nftitus.git
cp "$work/nftitus/titus-api-definitions/src/main/proto/netflix/titus/"*.proto .

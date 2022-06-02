#!/usr/bin/env bash
set -euvx
source $(dirname "$0")/lib.sh
make cross-linux
rsync -aPv build/bin/linux-amd64/ root@[%$(getDevAgentIP)]:/apps/titus-executor/bin/

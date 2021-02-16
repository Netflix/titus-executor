#!/bin/bash

set -euo pipefail

###############################################################################
# Resolve Titus environment
###############################################################################
# This might break if the user always intended to have allexport set
if [[ -e /etc/titus-executor/config.sh ]]; then
  set -o allexport
  . /etc/titus-executor/config.sh
  set +o allexport
fi

exec $(dirname "$0")/titus-executor-backend $@
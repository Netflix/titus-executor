#!/bin/bash

set -euo pipefail

###############################################################################
# Resolve Titus environment
###############################################################################

# This might break if the user always intended to have allexport set
if [[ -e /etc/titus-executor/metadata-proxy-config.sh ]]; then
  set -o allexport
  . /etc/titus-executor/metadata-proxy-config.sh
  set +o allexport
fi

exec /apps/titus-executor/bin/titus-inject-metadataproxy /apps/titus-executor/bin/titus-metadata-service --listener-fd=169
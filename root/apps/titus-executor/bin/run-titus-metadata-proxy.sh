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

export TOKEN_KEY_SALT=$(hostname)
exec /apps/titus-executor/bin/titus-inject-metadataproxy /apps/titus-executor/bin/titus-metadata-service --listener-fd=169
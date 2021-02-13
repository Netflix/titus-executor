#!/bin/bash

set -euo pipefail

if [[ -f "/run/is_kubelet" ]]; then
  export KUBELET_MODE=true
fi

exec /apps/titus-executor/bin/titus-logviewer

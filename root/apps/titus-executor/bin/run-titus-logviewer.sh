#!/bin/bash
set -euo pipefail
source /etc/titus-executor/config.sh
exec /apps/titus-executor/bin/titus-logviewer

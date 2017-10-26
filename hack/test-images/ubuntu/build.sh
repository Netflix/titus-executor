#!/bin/bash
set -euo pipefail

tag=$(date +%Y%m%d-%s)
image="titusoss/ubuntu-test:${tag}"

docker build -t $image .
docker push $image

echo "Built, and pushed: ${image}"

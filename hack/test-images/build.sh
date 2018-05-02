#!/bin/sh
set -euo pipefail

# Must be SH because that's what the builder in circle CI has
image_name=$1
echo "Building ${image_name}"

tag=$(date +%Y%m%d-%s)
image="titusoss/${image_name}:${tag}"
echo "Image name with tag: ${image}"

docker build -t $image ${image_name}/
docker push $image

echo "Built, and pushed: ${image}"

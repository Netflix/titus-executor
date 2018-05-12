#!/bin/sh
set -euo pipefail

# Must be SH because that's what the builder in circle CI has
image_name=$1
echo "Building ${image_name}"

tag=$(date +%Y%m%d-%s)
image="titusoss/${image_name}"
if [[ -v DOCKER_CUSTOM_REGISTRY ]]; then
	image="${DOCKER_CUSTOM_REGISTRY}/${image}"
fi

dated_image="${image}:${tag}"
echo "Image name with tag: ${dated_image}"

docker build -t $dated_image ${image_name}
docker push $dated_image

docker tag $dated_image ${image}:latest
docker push ${image}:latest

echo "Built, and pushed: ${dated_image}"

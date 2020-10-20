#!/bin/sh
set -eo pipefail

# Must be SH because that's what the builder in circle CI has
image_name=$1
echo "Building ${image_name}"

# Set the second argument to anything to enable this:
if [[ -n "${BUILD_FROM_CHECKOUT_ROOT}" ]]; then
    # This assumes that we're running in `hack/test-images/`, which
    #is what all of the docker commands assume anyway
    cd ../..
    echo "Setting current working directory to: ${PWD}"
fi

tag=$(date +%Y%m%d-%s)
image="titusoss/${image_name}"

dated_image="${image}:${tag}"
echo "Image name with tag: ${dated_image}"

if [[ -n "${BUILD_FROM_CHECKOUT_ROOT}" ]]; then
    docker build -t $dated_image -f hack/test-images/${image_name}/Dockerfile .
else
    docker build -t $dated_image ${image_name}
fi
if [[ -n "${DOCKER_CUSTOM_REGISTRY}" ]]; then
	IFS=','
	for registry in ${DOCKER_CUSTOM_REGISTRY}; do
		docker tag ${dated_image} ${registry}/${dated_image}
		docker push ${registry}/${dated_image}

		docker tag ${dated_image} ${registry}/${image}:latest
		docker push ${registry}/${image}:latest
	done
else
	docker push $dated_image

	docker tag $dated_image ${image}:latest
	docker push ${image}:latest
fi

echo "Built, and pushed: ${dated_image}"

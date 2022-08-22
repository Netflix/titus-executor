#!/usr/bin/env bash

set -eu -o pipefail -x

## Build all linux-amd64 binaries
mkdir -p build/bin/linux-amd64

# Go
export CGO_ENABLED=0
gox -gcflags="${GC_FLAGS:--N -l}" -osarch="linux/amd64 darwin/amd64" \
  -output="build/bin/{{.OS}}-{{.Arch}}/{{.Dir}}" -verbose ./cmd/...

# titus-mount helpers
make -C mount all
mv mount/titus-mount-block-device build/bin/linux-amd64/
mv mount/titus-mount-nfs build/bin/linux-amd64/
mv mount/titus-mount-bind build/bin/linux-amd64/
mv mount/titus-mount-container-to-container build/bin/linux-amd64/

# tini
make build/tini/tini-static
mv build/tini/tini-static build/bin/linux-amd64

# titus-nsenter
(
    rm -rf build/inject && mkdir -p build/inject
    cd build/inject
    TINI_INCLUDE_DIR=../tini/src TINI_LIBRARY_DIR=../build/tini cmake ../../inject
    make V=1
)
mv build/inject/titus-nsenter build/bin/linux-amd64
mv build/inject/titus-mnt build/bin/linux-amd64

install -t root/apps/titus-executor/bin build/bin/linux-amd64/*


## Setup the environment
outdir="$(mktemp -d)"
export git_sha=$(git rev-parse --verify HEAD)
export git_sha_short=${git_sha:0:8}
export version=${version:-$(git describe --tags --long)}
export iteration="--iteration ${ITERATION:-$(date +%s)}"

# when on CI/Jenkins
if [[ -n "${BUILD_NUMBER:-}" ]]; then
    last_tag=$(git describe --abbrev=0 --tags | sed 's/^[a-zA-Z]//')
    export version="${last_tag}-h${BUILD_NUMBER}.${git_sha_short}"
    unset iteration
fi

## Build the deb package
export BUILD_DATE=$(date -u +"%Y-%m-%d_%H:%M:%S")
nfpm package --target $outdir --packager deb
num_debs=$(find "$outdir" -iname "*.deb" | wc -l)
if [[ $num_debs -ne 1 ]]; then
    echo "Expected exactly one deb file in ${outdir}" >&2
    ls "$outdir" >&2
    exit 1
fi
filename=$(ls -t ${outdir}/*.deb | grep -v latest | head -n 1)

mkdir -p build/distributions
mv ${filename} build/distributions

echo "## Updating the symlink: titus-executor_latest.deb -> ${filename}" >&2
pushd build/distributions
ln -sf $(basename ${filename}) titus-executor_latest.deb
popd >/dev/null


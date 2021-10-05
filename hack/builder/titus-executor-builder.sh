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

install -t root/apps/titus-executor/bin build/bin/linux-amd64/*


## Setup the environment

outdir="$(mktemp -d)"
git_sha=$(git rev-parse --verify HEAD)
git_sha_short=${git_sha:0:8}
version=${version:-$(git describe --tags --long)}
iteration="--iteration ${ITERATION:-$(date +%s)}"

# when on CI/Jenkins
if [[ -n "${BUILD_NUMBER:-}" ]]; then
    last_tag=$(git describe --abbrev=0 --tags | sed 's/^[a-zA-Z]//')
    version="${last_tag}-h${BUILD_NUMBER}.${git_sha_short}"
    unset iteration
fi

# Build a tarball
mkdir -p build/tarball
install -t build/tarball build/bin/linux-amd64/*
tar  -czv -C build/tarball -f ${outdir}/titus-executor-${version}.tar.gz .

## Build the deb package

MAYBE_BRANCH=$(git rev-parse --abbrev-ref HEAD)

if [[ ${BUILDKITE_BRANCH:-$MAYBE_BRANCH} != "master" && "${ENABLE_DEV:-true}" == "true" ]]; then
    provides="--provides titus-executor-dev"
fi

cat <<-EOF >/tmp/post-install.sh
#!/bin/bash
systemctl --system daemon-reload
# TODO(Sargun): Make this reload apparmor only if apparmor is "started"
systemctl reload apparmor || echo "Could not reload apparmor"
EOF
chmod +x /tmp/post-install.sh

fpm -t deb -s dir -C root \
  -a amd64 \
  -n titus-executor \
  --maintainer titus-developers@netflix.com \
  ${iteration:-} \
  --version "$version" \
  --deb-field "Build-Host: ${BUILD_HOST:-}" \
  --deb-field "Build-Job: ${BUILD_JOB:-}" \
  --deb-field "Build-Number: ${BUILD_NUMBER:-}" \
  --deb-field "Build-Id: ${BUILD_ID:-}" \
  --deb-field "Implementation-Vendor: Netflix, Inc." \
  --deb-field "Built-By: fpm" \
  --deb-field "Built-OS: Linux" \
  --deb-field "Build-Date: $(date -u +"%Y-%m-%d_%H:%M:%S")" \
  --deb-field "Module-Owner: titus-developers@netflix.com" \
  --deb-field "Module-Email: titus-developers@netflix.com" \
  --deb-field "Module-Origin: ssh://git@github.com:Netflix/titus-executor.git" \
  --deb-field "Change: ${git_sha_short}" \
  --deb-field "Branch: ${git_sha}" \
  --deb-activate ldconfig \
  --depends libc6 \
  --depends 'apparmor >= 2.12' \
  --depends 'util-linux >= 2.31.1' \
  --deb-recommends 'docker-ce >= 5:18.09.1~3-0~ubuntu-xenial' \
  --deb-recommends lxcfs \
  --deb-recommends atlas-titus-agent \
  --deb-recommends nvidia-container-runtime-hook \
  ${provides:-} \
  --after-install /tmp/post-install.sh \
  --package "${outdir}/"

num_debs=$(find "$outdir" -iname "*.deb" | wc -l)
if [[ $num_debs -ne 1 ]]; then
    echo "Expected exactly one deb file in ${outdir}" >&2
    ls "$outdir" >&2
    exit 1
fi

filename=$(ls -t ${outdir}/*.deb | grep -v latest | head -n 1)

# TODO: only run the linter on the file above
# see: nebula/src/main/groovy/netflix/nebula/ospackage/NebulaOsPackageDebRepositoryPublish.groovy
lintian --suppress-tags dir-or-file-in-opt,statically-linked-binary,unstripped-binary-or-object,debian-changelog-file-missing-or-wrong-name,no-copyright-file,extended-description-is-empty,python-script-but-no-python-dep,non-standard-toplevel-dir,maintainer-name-missing,maintainer-address-malformed,maintainer-script-should-not-use-adduser-system-without-home \
  --no-tag-display-limit ${filename}

mkdir -p build/distributions
mv ${filename} build/distributions
mv ${outdir}/titus-executor-${version}.tar.gz build/distributions

echo "## Updating the symlink: titus-executor_latest.deb -> ${filename}" >&2
pushd build/distributions
ln -sf $(basename ${filename}) titus-executor_latest.deb
popd >/dev/null


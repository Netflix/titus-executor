#!/usr/bin/env bash

set -eu -o pipefail

go_pkg="${GO_PACKAGE:-github.com/Netflix/titus-executor}"
go_src_path="/go/src/$go_pkg"

mkdir -p "$(dirname "$go_src_path")"
ln -sf /src "$go_src_path"

pushd "$go_src_path"

## Build all linux-amd64 binaries
mkdir -p build/bin/linux-amd64

# Go
gox -gcflags="${GC_FLAGS:--N -l}" -osarch="linux/amd64 darwin/amd64" \
  -output="build/bin/{{.OS}}-{{.Arch}}/{{.Dir}}" -verbose ./cmd/...

# titus-mount
make -C mount
mv mount/titus-mount build/bin/linux-amd64/

# tini
(
    mkdir -p build/tini
    cd build/tini
    # TODO(sargun): RELWITHDEBINFO
    cmake -DCMAKE_BUILD_TYPE=Release ../../tini
    make V=1
)
mv build/tini/tini-static build/bin/linux-amd64

# metadata service injector
(
	mkdir -p build/inject-metadataproxy
	cd build/inject-metadataproxy
	cmake ../../inject-metadataproxy
	make V=1
)
mv build/inject-metadataproxy/titus-inject-metadataproxy build/bin/linux-amd64

install -t root/apps/titus-executor/bin build/bin/linux-amd64/*


## Build the deb package

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

# TODO: use all caps for env vars (it isn't for backwards compatibility)
if [[ -n "${devBuild:-}" ]]; then
    provides="--provides titus-executor-dev"
fi

cat <<-EOF >/tmp/post-install.sh
systemctl enable titus-darion.service
systemctl enable titus-reaper.service
EOF
chmod +x /tmp/post-install.sh


fpm -t deb -s dir -C /src/root \
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
  --deb-recommends atlas-titus-agent \
  ${provides:-} \
  --after-install /tmp/post-install.sh \
  --package "${outdir}/"

num_debs=$(find "$outdir" -iname "*.deb" | wc -l)
if [[ $num_debs -ne 1 ]]; then
    echo "Expected exactly one deb file in ${outdir}" >&2
    ls "$outdir" >&2
    exit 1
fi

filename=$(basename "$(find "$outdir" -iname "*.deb" | head -n 1)")

# TODO: only run the linter on the file above
# see: nebula/src/main/groovy/netflix/nebula/ospackage/NebulaOsPackageDebRepositoryPublish.groovy
lintian --suppress-tags statically-linked-binary,unstripped-binary-or-object,debian-changelog-file-missing-or-wrong-name,no-copyright-file,extended-description-is-empty,python-script-but-no-python-dep,non-standard-toplevel-dir,maintainer-name-missing,maintainer-address-malformed,maintainer-script-should-not-use-adduser-system-without-home \
  --no-tag-display-limit "${outdir}/${filename}"

mv "${outdir}"/titus-executor_"${version}"*.deb /dist

echo "## Updating the symlink: titus-executor_latest.deb -> ${filename}" >&2
ln -sf "$filename" /dist/titus-executor_latest.deb

popd >/dev/null

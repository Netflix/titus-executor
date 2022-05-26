#!/usr/bin/env bash
set -eu
make cross-linux
for cell in test_us-east-1_staging01cell001 test_us-east-1_staging01cell002; do
  kubectx $cell
  for node in $(kubectl get nodes -o json | jq -r .items[].metadata.name); do
    rsync -aPv build/bin/linux-amd64/ root@$node:/apps/titus-executor/bin/
  done
done

#!/usr/bin/env bash
set -euvx
REGION=us-west-2
ENV=test
source $(dirname "$0")/lib.sh
make cross-linux

for IP in $(newt instance-lookup  --format '{{ .IP }}'  %titusvpcservice,$ENV,$REGION); do
rsync -aPv build/bin/linux-amd64/titus-vpc-service root@$IP:/apps/titus-executor/bin/

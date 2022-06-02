#!/usr/bin/env bash
REGION=us-east-1
ENV=prod
set -euvx
make cross-linux

for IP in $(newt instance-lookup  --format '{{ .InstanceId }}'  %titusvpcservice,$ENV,$REGION); do
  rsync -aPv build/bin/linux-amd64/titus-vpc-service root@$IP:/apps/titus-executor/bin/
  ssh $IP -- sudo systemctl restart titus-vpc-service.service
done

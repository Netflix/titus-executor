#!/bin/bash
set -vxue

make cross-linux
rsync -aPv build/bin/linux-amd64/titus-vpc-service %titusvpcservice,prod,us-east-1,0:/apps/titus-executor/bin/titus-vpc-service-adhoc-build
ssh %titusvpcservice,prod,us-east-1,0 -- "source /etc/titus-vpc-service/prod-us-east-1.sh; /apps/titus-executor/bin/titus-vpc-service-adhoc-build adhoc"

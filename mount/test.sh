#!/usr/bin/env bash
# This is a test harness for experimenting with
# the statically-linked titus-mount command
# in a scratch container.
set -vxeu
make
sudo docker run $(sudo docker build -q . ) ./titus-mount

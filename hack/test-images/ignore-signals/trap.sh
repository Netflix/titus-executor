#!/bin/bash
trap '' SIGINT SIGTERM
touch /tmp/foo
sleep 30
echo completed normally

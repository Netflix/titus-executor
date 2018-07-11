#!/bin/bash
trap '' SIGINT SIGTERM
touch /tmp/foo
sleep 120
echo completed normally

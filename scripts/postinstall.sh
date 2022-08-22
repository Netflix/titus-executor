#!/bin/bash
systemctl --system daemon-reload
# TODO(Sargun): Make this reload apparmor only if apparmor is "started"
systemctl reload apparmor || echo "Could not reload apparmor"

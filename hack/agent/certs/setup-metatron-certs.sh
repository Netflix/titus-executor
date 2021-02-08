#!/bin/bash

#
# Ensures that the test metatron certs are in the right location in /run.
# /run is mounted from the host, so we can't just add the certs to that
# directory at build time.
#

function die() {
    echo "Error: $*"
    exit 1
}

SRC_CERT_DIR=/metatron/certificates
# Allow metatron certs to be mounted in to override the default location
MNT_SRC_CERT_DIR=/mnt/metatron/certificates
DEST_CERT_DIR=/run/metatron/certificates

if [[ -e $MNT_SRC_CERT_DIR ]]; then
    SRC_CERT_DIR=$MNT_SRC_CERT_DIR
fi

if [[ ! -d $SRC_CERT_DIR ]]; then
    die "Source certificate directory does not exist: $SRC_CERT_DIR"
fi

ls $SRC_CERT_DIR | grep -q client
if [[ $? -ne 0 ]]; then
    echo "Contents of $SRC_CERT_DIR:"
    ls $SRC_CERT_DIR
    die "No certificates in source cert directory: $SRC_CERT_DIR"
fi

if [[ ! -d $DEST_CERT_DIR ]]; then
    mkdir -p $DEST_CERT_DIR
fi

# Don't overwrite existing files
cp -n $SRC_CERT_DIR/client.* $DEST_CERT_DIR/

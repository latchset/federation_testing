#!/bin/bash

#################

set -x
set -e

if [ -f /etc/os-release ]; then
    . /etc/os-release
    VER_MAJOR=$(echo $VERSION_ID|cut -f1 -d.)
    VER_MINOR=$(echo $VERSION_ID|cut -f2 -d.)
fi

if [ "$ID" = "rhel" -o "$ID" = "centos" ] && [ $VER_MAJOR -lt 10 ]; then
    ./test_khci_mellon.sh
fi

./test_khci_oidc.sh


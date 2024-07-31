#!/bin/bash

set -e

echo -e '\n\n'
if [ "$ID" = "rhel" -o "$ID" = "centos" ] && [ $VER_MAJOR -lt 10 ]; then
    echo "First running mod_auth_mellon tests"
    ./test_mellon.sh
fi
echo -e '\n\n'
echo "Now run xmlsec1 tests"
echo -e '\n\n'

dnf -y install xmlsec1 xmlsec1-openssl

py.test-3 -v test_xmlsec.py --junit-xml=result_xmlsec.xml


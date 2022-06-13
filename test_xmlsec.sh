#!/bin/bash

set -e

echo -e '\n\n'
echo "First running mod_auth_mellon tests"
./test_mellon.sh
echo -e '\n\n'
echo "Next run xmlsec1 tests"
echo -e '\n\n'

dnf -y install xmlsec1 xmlsec1-openssl

py.test-3 -v test_xmlsec.py


#!/bin/bash

set -e
source /etc/os-release
MAJOR_VERSION=${VERSION_ID:0:1}
MAJOR_VERSION=${MAJOR_VERSION:=0}

echo -e '\n\n'
echo "First running kchi tests"
./test_khci.sh
echo -e '\n\n'
echo "Next run python_oauthlib tests"
echo -e '\n\n'

py.test-3 -v test_python_oauthlib.py

#!/bin/bash

set -x 
set -e

echo "First running mod_auth_mellon tests"
./test_mellon.sh

echo "Next run lasso sha1 test."
python3 test-lasso-sha1.py

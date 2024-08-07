#!/bin/bash

#################

set -x
set -e

echo "Running mod_auth_openidc tests"
./test_oidc.sh

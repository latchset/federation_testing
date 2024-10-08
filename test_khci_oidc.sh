#!/bin/bash

#################

set -x
set -e

echo "Running mod_auth_openidc tests"
./setup.sh
./test_oidc.sh

./setup.sh /auth
./test_oidc.sh /auth

./setup.sh /newauth
./test_oidc.sh /newauth

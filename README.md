# fedcomp_gating

Gating tests for IdM related Federation Components

To use these tests, clone repo to local system and run:

## First setup test environment on system

cd fedcomp_gating
./setup.sh

## To run tests for mod_auth_mellon:

./test_mellon.sh

## To run tests for mod_auth_openidc:

./test_oidc.sh

## To run tests for keycloak-httpd-client-install:

./test_khci.sh

## To run tests for lasso

./test_lasso.sh

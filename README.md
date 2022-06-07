# Gating tests for IdM related Federation Components

To use these tests, clone repo to local system and run:

## First setup test environment on system

```sh
cd federation_components
./setup.sh
```

## To run tests for mod_auth_mellon

```sh
./test_mellon.sh
```

## To run tests for mod_auth_openidc

```sh
./test_oidc.sh
```

## To run tests for keycloak-httpd-client-install

```sh
./test_khci.sh
```

## To run tests for lasso

```sh
./test_lasso.sh
```

## To run tests for xmlsec

```sh
./test_xmlsec.sh
```


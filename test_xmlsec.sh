#!/bin/bash

set -e
source /etc/os-release
MAJOR_VERSION=${VERSION_ID:0:1}
MAJOR_VERSION=${MAJOR_VERSION:=0}

echo -e '\n\n'
echo "First running mod_auth_mellon tests"
./test_mellon.sh
echo -e '\n\n'
echo "Next run xmlsec1 tests"
echo -e '\n\n'

function check_result {
    actual_rc=$?
    expected_rc=$1
    test_name=$2
    echo -n "# Result $test_name "
    if [ $actual_rc -eq $expected_rc ]; then
        echo "succeeded"
    else
        echo "failed"
    fi
}

dnf -y install xmlsec1 xmlsec1-openssl

echo -e "\n\n"
echo "###############################################################"
echo "Test 1: confirm you can sign and verify xml with sha-256"
echo "###############################################################"
./xmlsec-sign-verify.sh xmlsec_data/book-template-sha256.xml /tmp/https/tls.key
check_result 0 testSignAndVerifyWithSha256


if [ "$MAJOR_VERSION" -lt 9 ]; then
    echo "Older than RHEL9.  Ending tests cleanly"
    exit 0
fi

echo -e "\n\n"
echo "###############################################################"
echo "Test 2: confirm you cannot sign xml with sha-1"
echo "###############################################################"
set +e
./xmlsec-sign-verify.sh xmlsec_data/book-template-sha1.xml /tmp/https/tls.key
check_result 1 testCannotSignWithSha1

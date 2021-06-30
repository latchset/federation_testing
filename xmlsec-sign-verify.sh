#!/bin/bash

echo "Sign and verify a XML template"
template=$1
private_key=$2

if [ -z $template -o ! -f $template ]; then
    echo "Usage: sign-verify.sh template private_key"
    exit 1
fi

if [ -z $private_key -o ! -f $private_key ]; then
    echo "Usage: sign-verify.sh template private_key"
    exit 1
fi

outfile=${template%.xml}-output.xml
rm -f $outfile

echo "Signing a document"
xmlsec1 --sign --output $outfile --privkey-pem $private_key $template
rv=$?

if [ $rv -ne 0 ]; then
    echo "Could not sign document"
    exit 1
fi

echo "Signing OK, verifying using the embedded pubkey"
xmlsec1 --verify $outfile
if [ $rv -ne 0 ]; then
    echo "Could not verify document"
    exit 1
fi


#!/usr/bin/env bash

usage() {
    echo "USAGE create_signing_keys.sh"
    echo ""
    echo "create_signing_keys.sh DIRECTORY"
    echo ""
    echo "DIRECTORY is the target directory where the keys will"
    echo "be created."
    echo ""
    echo "Example:"
    echo "./create_signing_keys.sh /var/lib/passwordless/keys"
}

DATE=$(date +%s)
if [ ! $# -eq 1 ]
then
       usage
       exit 1
fi

mkdir -p $1
cd $1
openssl genrsa -out ${DATE}.key
openssl rsa -in ${DATE}.key -pubout > ${DATE}.pub
cd ..

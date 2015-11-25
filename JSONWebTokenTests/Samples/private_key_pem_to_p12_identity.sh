#!/bin/bash

INPUT=$1
DIRECTORY=`dirname "$INPUT"`
FILENAME=`basename "$INPUT"`
TARGET_BASE_PATH="$DIRECTORY"/"${FILENAME%%.*}"
echo $1
echo $TARGET_BASE_PATH
echo "$TARGET_BASE_PATH".csr
echo "$TARGET_BASE_PATH".crt

#Create a certificate signing request with the private key
openssl req -new -key $1 -out "$TARGET_BASE_PATH".csr

#Create a self-signed certificate with the private key and signing request
openssl x509 -req -days 3650 -in "$TARGET_BASE_PATH".csr -signkey $INPUT -out "$TARGET_BASE_PATH".crt

#Convert the certificate to DER format: the certificate contains the public key
openssl x509 -outform der -in "$TARGET_BASE_PATH".crt -out "$TARGET_BASE_PATH".der

#Export the private key and certificate to p12 file
openssl pkcs12 -export -out "$TARGET_BASE_PATH".p12 -inkey $INPUT -in "$TARGET_BASE_PATH".crt
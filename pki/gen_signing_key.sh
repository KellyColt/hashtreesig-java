#! /usr/bin/env bash

#openssl ecparam -name brainpoolP256r1 -genkey -out vau_key.pem
openssl ecparam -name prime256v1 -genkey -out signing_key.pem

openssl req -x509 -key signing_key.pem \
-out signer_cert.pem -days $((365*5)) \
-subj "/C=DE/ST=Berlin/L=Berlin/O=gematik/OU=gematik/CN=Hashtree-Signer-Example"


#!/usr/bin/env bash
# Crea una CA de laboratorio y un certificado de servidor para localhost.
# En producción: certificado de una CA pública (Let's Encrypt) o la PKI institucional.
set -euo pipefail
mkdir -p certs && cd certs
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -keyout ca.key -out ca.crt -subj "/CN=MASI Lab CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server.key -out server.csr -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n" > ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 30 -out server.crt -extfile ext.cnf 2>/dev/null
chmod 644 ca.crt server.crt
rm -f server.csr ext.cnf
echo "Certificados en ./certs (server.key con permisos 600)"

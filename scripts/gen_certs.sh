#!/usr/bin/env bash
# Creates a private lab CA and a server certificate for shield.local (SAN: shield.local, waf, localhost, 127.0.0.1).
set -euo pipefail
cd "$(dirname "$0")/../certs"
if [ -s server.crt ] && [ -s server.key ] && [ -s ca.crt ]; then echo "certs already present"; exit 0; fi
openssl req -x509 -newkey rsa:4096 -nodes -days 825 -keyout ca.key -out ca.crt -subj "/CN=ShieldWall Lab CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=shield.local" 2>/dev/null
printf "subjectAltName=DNS:shield.local,DNS:waf,DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > san.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 397 -sha256 -extfile san.ext 2>/dev/null
chmod 644 server.key ca.crt server.crt
rm -f server.csr san.ext ca.srl
echo "certs generated in $(pwd)"

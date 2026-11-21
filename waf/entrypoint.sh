#!/bin/sh
# Renders configuration from environment variables, then runs nginx in the foreground (PID 1).
set -eu

: "${SHIELD_MODE:=on}" "${UPSTREAM:=juiceshop:3000}" "${HTTPS_PUBLIC_PORT:=8443}"
: "${PARANOIA:=2}" "${INBOUND_THRESHOLD:=5}" "${LOGIN_RATE:=5r/m}" "${LOGIN_BURST:=5}"
: "${GENERAL_RATE:=50r/s}" "${GENERAL_BURST:=200}" "${SERVER_NAME:=shield.local}"

case "$SHIELD_MODE" in
  on)     RULE_ENGINE=On;            RATE_DRY_RUN=off ;;
  detect) RULE_ENGINE=DetectionOnly; RATE_DRY_RUN=on  ;;
  off)    RULE_ENGINE=Off;           RATE_DRY_RUN=on  ;;
  *) echo "invalid SHIELD_MODE=$SHIELD_MODE (on|detect|off)" >&2; exit 1 ;;
esac
export RULE_ENGINE RATE_DRY_RUN UPSTREAM HTTPS_PUBLIC_PORT PARANOIA INBOUND_THRESHOLD \
       LOGIN_RATE LOGIN_BURST GENERAL_RATE GENERAL_BURST SERVER_NAME

envsubst '${UPSTREAM} ${HTTPS_PUBLIC_PORT} ${LOGIN_RATE} ${LOGIN_BURST} ${GENERAL_RATE} ${GENERAL_BURST} ${RATE_DRY_RUN} ${SERVER_NAME}' \
  < /etc/nginx/templates/nginx.conf.template > /etc/nginx/nginx.conf
envsubst '${RULE_ENGINE} ${PARANOIA} ${INBOUND_THRESHOLD}' \
  < /etc/nginx/modsec/main.conf.template > /etc/nginx/modsec/main.conf

# Fallback certificate so the container still starts if `make certs` was skipped.
if [ ! -s /etc/nginx/certs/server.crt ] || [ ! -s /etc/nginx/certs/server.key ]; then
  echo "[entrypoint] no certificate mounted, generating a throwaway self-signed one"
  mkdir -p /tmp/certs
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=${SERVER_NAME}" \
    -addext "subjectAltName=DNS:${SERVER_NAME},DNS:localhost" \
    -keyout /tmp/certs/server.key -out /tmp/certs/server.crt 2>/dev/null
  sed -i 's#/etc/nginx/certs/#/tmp/certs/#g' /etc/nginx/nginx.conf
fi

[ -f /etc/nginx/dynamic/blocklist.conf ] || : > /etc/nginx/dynamic/blocklist.conf
touch /var/log/shield/access.json /var/log/shield/nginx_error.log
echo "[entrypoint] mode=$SHIELD_MODE engine=$RULE_ENGINE paranoia=$PARANOIA threshold=$INBOUND_THRESHOLD"
nginx -t
exec nginx -g 'daemon off;'

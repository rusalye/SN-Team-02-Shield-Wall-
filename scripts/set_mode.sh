#!/usr/bin/env bash
# Switch ShieldWall between on (block), detect (log only) and off (unprotected baseline).
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:?usage: set_mode.sh on|detect|off}"
case "$mode" in on|detect|off) ;; *) echo "mode must be on, detect or off" >&2; exit 1 ;; esac
touch .env
grep -v '^SHIELD_MODE=' .env > .env.tmp || true
echo "SHIELD_MODE=$mode" >> .env.tmp
mv .env.tmp .env
docker compose up -d --force-recreate --no-deps waf
docker compose up -d --force-recreate --no-deps sentinel   # shares waf's PID namespace, must restart with it
for _ in $(seq 1 40); do
  docker compose exec -T waf curl -fs http://127.0.0.1/healthz >/dev/null 2>&1 && { echo "ShieldWall mode: $mode"; exit 0; }
  sleep 1
done
echo "waf did not become healthy, check: docker compose logs waf" >&2; exit 1

#!/usr/bin/env bash
# End-to-end demo: unprotected baseline -> protected run -> reports.
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p reports
SENTINEL="http://127.0.0.1:$(grep -E '^SENTINEL_PORT=' .env | cut -d= -f2 | grep . || echo 9000)"
unban() { curl -fs -X POST -d '{"all":true}' "$SENTINEL/api/unban" >/dev/null || true; }
h() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

h "1/4  Baseline: WAF OFF (attacks should reach the app)"
./scripts/set_mode.sh off
docker compose run --rm -T attacker python attack_replay.py --label 1_attack_baseline_waf_off

h "2/4  Protected: WAF ON"
./scripts/set_mode.sh on
unban

h "3/4  Benign traffic must flow (>=95% allowed)"
docker compose run --rm -T client python benign_replay.py --label 2_benign_waf_on

h "4/4  Attack replay must be fully blocked, brute force auto-banned"
docker compose run --rm -T attacker python attack_replay.py --expect block --label 3_attack_waf_on
sleep 4
curl -fs "$SENTINEL/report.md" -o reports/4_alert_summary.md && echo "alert summary -> reports/4_alert_summary.md"
curl -fs "$SENTINEL/api/navigator-layer" -o reports/5_attack_navigator_layer.json && echo "ATT&CK layer -> reports/5_attack_navigator_layer.json"
echo "Dashboard: $SENTINEL"

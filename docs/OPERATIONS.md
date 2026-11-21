# Operations guide

## 1. Configuration reference (`.env`)

| Variable | Default | Meaning |
|---|---|---|
| `SHIELD_MODE` | `on` | `on` block, `detect` log only (rate limits dry-run, no bans), `off` unprotected baseline |
| `HTTP_PORT` / `HTTPS_PORT` | 8080 / 8443 | Published host ports of the edge |
| `SENTINEL_PORT` | 9000 | Dashboard and API port on `127.0.0.1` |
| `PARANOIA` | 2 | CRS paranoia level 1 to 4 |
| `INBOUND_THRESHOLD` | 5 | Anomaly score needed to block |
| `LOGIN_RATE` / `LOGIN_BURST` | `5r/m` / 5 | Rate limit on `/rest/user/login` and `/rest/user/reset-password` |
| `GENERAL_RATE` / `GENERAL_BURST` | `50r/s` / 200 | Rate limit for all other paths |
| `BAN_STRIKES` | 20 | Weighted strikes inside the window that trigger a ban |
| `STRIKE_WINDOW` | 120 | Window in seconds |
| `BAN_STEPS` | `300,1800,86400` | Ban seconds for the 1st, 2nd, 3rd+ offense |
| `ALLOWLIST` | `127.0.0.1,::1,172.28.0.1` | Sources Sentinel never bans |
| `SENTINEL_TOKEN` | empty | If set, `POST /api/unban` requires header `X-Token` |

Changing `.env` values needs a container recreate: `docker compose up -d --force-recreate waf sentinel`. `make mode-*` does this for the mode.

## 1a. Attack Console (Streamlit, `http://127.0.0.1:8501`)

Runs as the `console` service with fixed IP `172.28.0.102` on the `edge` and `mgmt` networks. It imports the attack catalog from `lab/tests/attack_replay.py`, so it matches `make attack`. Tabs: **Attack lab** (select all or by class, tick individual attacks, brute-force attempt count, pause between requests, free-form request builder, CSV export), **Live defense view** (refreshes every 3 s from Sentinel), **How it works**. The sidebar shows the current mode and an "Unban all" button. The target host is fixed to the lab WAF, so it cannot be pointed elsewhere from the UI. The console's IP is deliberately not allowlisted, so its attacks trigger real auto-bans; click "Unban all" between runs. It is bound to loopback only and has no authentication, so do not expose port 8501.

## 2. Sentinel HTTP API (`http://127.0.0.1:9000`)

| Method and path | Purpose |
|---|---|
| `GET /` | Dashboard |
| `GET /api/summary` | KPIs, by-type breakdown, top IPs and rules, techniques, timeline, bans |
| `GET /api/events?limit=50&ip=<ip>&blocked=1` | Recent events (limit up to 1000) |
| `GET /api/bans` | Active bans |
| `GET /present` | Presenter view: architecture, layer map, before/after, scorecard |
| `GET /api/evidence` | Replay reports from `./reports` (mounted read-only) |
| `GET /report.md` | Alert summary in Markdown |
| `GET /api/navigator-layer` | ATT&CK Navigator layer |
| `GET /metrics` | Prometheus metrics |
| `POST /api/unban` | Body `{"ip":"x.x.x.x"}` or `{"all":true}` |

## 3. Pre-event checklist

1. `docker compose build && docker compose pull juiceshop` on a good connection. The image build downloads Debian packages and the CRS tarball, so do it before the event (the brief warns about venue Wi-Fi). Bring a mobile hotspot.
2. `make up`, wait until `docker compose ps` shows `waf` healthy, then `make demo` end to end at least twice.
3. `make test` passes.
4. Record real numbers in `docs/TUNING.md` and `docs/TESTING.md`.
5. Confirm framework versions in `docs/ATTACK-MAPPING.md`.
6. Copy `reports/` into the submission and screenshot the dashboard.
7. Windows users: run inside WSL2 and keep the repo in the WSL filesystem. `.gitattributes` forces LF line endings on shell scripts and templates, which Docker needs.

## 4. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `waf` restarts or unhealthy | Config error | `docker compose logs waf` shows the `nginx -t` result |
| Port already in use | Another service on 8443 or 9000 | Set `HTTPS_PORT` / `SENTINEL_PORT` in `.env`, recreate |
| Benign client blocked right after an attack run | Residual ban or rate limit | `make unban`, wait a minute, retry |
| A benign request is blocked | False positive | `make fp`, then follow TUNING.md |
| `nginx master not found` in Sentinel logs | Sentinel and waf no longer share a PID namespace (one was recreated alone) | `docker compose up -d --force-recreate waf sentinel` or use `make mode-on` |
| Ban recorded but traffic still passes | Blocklist not reloaded | `docker compose exec waf cat /etc/nginx/dynamic/blocklist.conf`; check Sentinel logs |
| TLS verify error from the host | Not using the lab CA or hostname | Use `--cacert certs/ca.crt --resolve shield.local:8443:127.0.0.1`, or delete `certs/*` and `make certs` |
| Dashboard empty | No traffic yet, or log files missing | Run `make benign`; check `docker compose logs sentinel` |
| Scripts fail with `^M` errors | CRLF line endings | Re-checkout with LF, or `dos2unix scripts/*.sh waf/entrypoint.sh` |

Reset everything: `make clean` (removes volumes and generated reports). `make down` keeps the data volumes.

## 5. Known limitations and things to verify

These are honest notes for the team and for judge Q&A.

1. **Not yet measured.** The tuning log and acceptance "Observed" columns are blank by design. Fill them from a real run.
2. **Honeypot probes in the attack replay may be masked by the ban.** The honeypot checks run last, after the brute-force burst has normally triggered an auto-ban, so those three requests may be answered by `blocked-ip` instead of the honeypot rule. They still count as blocked, but the demo does not prove the honeypot rule in isolation. To demonstrate it: `make unban`, then `curl --cacert certs/ca.crt --resolve shield.local:8443:127.0.0.1 -i https://shield.local:8443/.env` from the attacker container or from an address that is not allowlisted, and show the ban in the dashboard. Moving the honeypot probes before the brute-force step in `attack_replay.py` would also fix it.
3. **Ban latency.** Bans reach nginx within about two to three seconds (log tail, strike count, 2-second sweep, reload).
4. **Per-IP controls only.** See THREAT-MODEL.md.
5. **Response bodies are not inspected**, so data-leak rules are inactive.
6. **Allowlisted gateway.** Host traffic is not auto-banned in the default configuration.
7. **Upstream drift.** Debian `trixie-slim` and the ModSecurity/nginx packages float; CRS and Juice Shop are pinned. For a frozen build, pin package versions or save the built image with `docker save`.

# ShieldWall

**Edge protection for a vulnerable public-facing web application.** Hackathon problem statement PS6, *Shield Wall*, from the Secure Networks Hackathon.

A legacy application cannot be patched this week, so ShieldWall protects it at the network edge: TLS termination, a ModSecurity v3 WAF with the OWASP Core Rule Set (CRS), per-IP rate limiting, and a closed-loop response engine called **Sentinel** that turns WAF decisions into automatic, escalating bans and maps every alert to MITRE ATT&CK.

```
 attacker / user ──HTTPS──▶  nginx + ModSecurity v3 + CRS 4.7  ──HTTP──▶  OWASP Juice Shop (isolated network)
                              │  honeypots · virtual patches · rate limits
                              ▼  JSON audit + access logs
                          Sentinel ── strikes → escalating bans → nginx blocklist (SIGHUP reload)
                              └── dashboard · alert summary · ATT&CK Navigator layer · /metrics
```

## What makes it different

| # | Feature | Why it matters to a judge |
|---|---|---|
| 1 | **Closed-loop auto-defense.** Sentinel tails WAF logs, scores strikes per source, and bans with escalating durations (5 min, 30 min, 24 h). | The brief asks for "automatic blocking for login brute force". This goes further: any repeat offender is cut off. |
| 2 | **Honeypot tripwires.** Decoy paths (`/.env`, `/.git/`, `/wp-login.php` ...) that no legitimate user requests. One hit means an instant ban. | Near-zero false positives, catches reconnaissance before an exploit is attempted. |
| 3 | **Virtual patches for Juice Shop flaws.** Three app-specific rules (NoSQL operator injection, B2B order RCE, `/ftp` null-byte bypass). | Delivers the stretch goal, and shows the "can't patch this week" story. |
| 4 | **Three-mode switch (`off` / `detect` / `on`).** | A live before/after demo: the same attacks succeed with the WAF off and fail with it on. |
| 5 | **Evidence mapped to standards.** Every alert carries ATT&CK technique, CWE and CAPEC; Sentinel exports an ATT&CK Navigator layer and a Markdown alert summary. | Matches the "alert summary by attack type" deliverable and the judges' mapping sheet. |
| 6 | **Hardened by design.** No Docker socket mount, dropped capabilities, `no-new-privileges`, backend network is `internal`, client-supplied `X-Forwarded-For` is overwritten. | The protection layer is not itself a weak link. |
| 7 | **Interactive Attack Console.** A Streamlit UI where a reviewer selects attack classes or individual attacks (or all), crafts their own request, fires them, and watches blocks, bans and ATT&CK mapping update live. | Judges drive the demo themselves instead of watching a script. |
| 8 | **One-command reproducibility.** `make up && make demo`. | Judges can re-run everything on their own laptop. |

## Quickstart

Requirements: Docker with Compose v2, GNU make, about 2 GB of free disk. Linux, macOS or WSL2.

```bash
cp .env.example .env     # optional, defaults work
make up                  # lab CA + cert, build, start juiceshop + waf + sentinel
make demo                # baseline (WAF off) -> protected -> reports in ./reports
```

| Command | What it does | Pass condition |
|---|---|---|
| `make benign` | 27 normal requests (browse, search, register, login, basket) | at least 95% allowed (exit 0) |
| `make attack` | 20 attack checks: 16 payloads in 6 classes + brute-force burst + 3 honeypot probes | 100% blocked (exit 0) |
| `make fp` | Shows which rules blocked the benign client | tuning helper |
| `make mode-on / mode-detect / mode-off` | Switch protection mode | |
| `make report` | Writes alert summary + Navigator layer to `reports/` | |
| `make unban` | Clears all bans (needed between repeated attack runs) | |

Endpoints: app `https://localhost:8443` (only reachable through the WAF), dashboard `http://127.0.0.1:9000`.
The lab CA is `certs/ca.crt`; use `curl --cacert certs/ca.crt --resolve shield.local:8443:127.0.0.1 https://shield.local:8443/` for a verified connection.

## Deliverables checklist (PS6)

| Required deliverable | Where |
|---|---|
| Proxy and WAF configuration | `waf/` (nginx, ModSecurity, CRS setup, custom rules) |
| Both scripts | `lab/tests/attack_replay.py`, `lab/tests/benign_replay.py` |
| Tuning notes | [docs/TUNING.md](docs/TUNING.md) |
| Alert summary | generated at `reports/4_alert_summary.md` by `make demo` |
| ATT&CK mapping | [docs/ATTACK-MAPPING.md](docs/ATTACK-MAPPING.md) and `reports/5_attack_navigator_layer.json` |

| Core task | How it is met | Evidence |
|---|---|---|
| 1. nginx + ModSecurity + CRS with TLS termination | `waf/` image, TLS 1.2/1.3 only, AEAD ciphers | [ARCHITECTURE](docs/ARCHITECTURE.md) |
| 2. Block every attack, allow at least 95% benign | CRS PL2 + custom rules + exclusions | `reports/3_attack_waf_on.json`, `reports/2_benign_waf_on.json` |
| 3. Rate limiting and automatic blocking for brute force | `limit_req` on login endpoints + Sentinel bans | demo step 4 |
| 4. Centralised logs, alert summary by attack type | shared log volume, SQLite store, `/report.md` | `reports/4_alert_summary.md` |
| Stretch: virtual patch, dashboard | `20-virtual-patches.conf`, `dashboard.html` | |

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, networks, request lifecycle, ban feedback loop, data model |
| [docs/DESIGN-DECISIONS.md](docs/DESIGN-DECISIONS.md) | Why each choice was made and which alternatives were skipped |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | What is protected, trust boundaries, residual risk of ShieldWall itself |
| [docs/ATTACK-MAPPING.md](docs/ATTACK-MAPPING.md) | ATT&CK, D3FEND, CWE, CAPEC and mitigation mapping per control |
| [docs/TUNING.md](docs/TUNING.md) | False-positive workflow, exclusions in use, tuning log |
| [docs/TESTING.md](docs/TESTING.md) | Acceptance tests, judge-variation commands, expected results |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Configuration reference, API, troubleshooting, known limitations |
| [docs/DEMO-SCRIPT.md](docs/DEMO-SCRIPT.md) | 6-minute live demo script and fallback plan |

## Repository layout

```
shieldwall/
├── docker-compose.yml        # juiceshop, waf, sentinel (+ attacker/client under the "lab" profile)
├── Makefile  .env.example
├── waf/                      # edge image
│   ├── Dockerfile  entrypoint.sh  nginx.conf.template
│   ├── snippets/proxy_common.conf
│   └── modsec/               # modsecurity.conf, main.conf.template, shield-setup.conf,
│       └── rules-before/ (00-honeypot, 10-juiceshop-exclusions, 20-virtual-patches) · rules-after/
├── sentinel/sentinel/        # engine, tailer, store, attackmap, insights, api, nginx_ctl, static/dashboard.html
├── console/                  # Streamlit Attack Console (app.py UI, lab.py logic, tests/)
├── lab/tests/                # attack_replay.py, benign_replay.py, common.py
├── scripts/                  # gen_certs.sh, set_mode.sh, demo.sh
├── certs/  reports/          # generated, git-ignored
└── docs/
```

## Rules of engagement

Attacks run only against the containers in this repository, on your own machine. Do not point `attack_replay.py` at any other host (set `TARGET` only to your own lab).

## Third-party components and attribution

OWASP Juice Shop (MIT, pinned `v17.1.1`), nginx, ModSecurity v3 and its nginx connector (Debian packages), OWASP Core Rule Set `4.7.0` (Apache-2.0). The WAF configuration, custom rules, Sentinel, test scripts and documentation are the team's own work. *Team: add your AI-assistant disclosure here if the organizers' policy requires one.*

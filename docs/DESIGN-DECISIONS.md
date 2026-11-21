# Design decisions and rejected alternatives

Each entry states what we chose, why, and what we deliberately did not do. The hackathon is five hours, so "simple, explainable and reproducible" was weighted heavily.

## D1. Target application: OWASP Juice Shop

**Chosen.** One container, no database setup, a modern JSON REST API plus an Angular SPA, and many documented vulnerabilities (SQLi, XSS, traversal, NoSQL injection, RCE paths). Pinned to `v17.1.1` so results are repeatable.

| Alternative | Why not |
|---|---|
| DVWA | Needs PHP + MySQL, mostly form-based pages. It is simpler to protect, which makes for a less convincing demo of JSON-body inspection and false-positive tuning. |
| WebGoat / crAPI / bWAPP | Heavier to start, or less well known to judges. |
| A custom vulnerable app | Costs build time and invites "you wrote the weakness to match your rules" doubts. |

## D2. WAF engine: nginx + ModSecurity v3 + OWASP CRS

**Chosen.** The problem statement names this stack, Debian packages the nginx connector so the image builds in one `apt-get`, and CRS is the industry baseline judges recognise.

| Alternative | Why not |
|---|---|
| Coraza (Go, CRS compatible) | A good, actively developed option. Skipped because the packaged ModSecurity route builds faster and matches the brief literally. Our rules are plain SecLang, so migrating later is mostly a matter of swapping the engine. |
| ModSecurity v2 on Apache | Older architecture and a heavier image. |
| SafeLine, Cloudflare, AWS WAF | Managed or opaque rule engines. The brief asks for configuration the team can show and tune. |
| Hand-written regex rules only | Weak coverage and many bypasses. CRS provides tested coverage; we add only app-specific rules on top. |

## D3. CRS settings: paranoia level 2, threshold 5, anomaly scoring

**Chosen.** PL2 catches more encoded and obfuscated payloads than PL1 and is still tunable in the time available. Threshold 5 means one critical match blocks. Both are environment variables, so the demo can show the trade-off.

| Alternative | Why not |
|---|---|
| PL1 | Fewer false positives, but weaker against evasion variants a judge might try. |
| PL3 or PL4 | Many false positives against a JSON API, which would need long tuning. Documented as a hardening option once tuned. |
| Traditional (non-anomaly) mode | Blocks on the first match with no scoring, which makes tuning coarse. |

## D4. Response engine: custom "Sentinel" instead of fail2ban or a SIEM

**Chosen.** About 500 lines of dependency-free Python. It understands ModSecurity JSON audit records, weights signals, escalates bans, enriches alerts with ATT&CK/CWE/CAPEC and renders the dashboard. This is the main differentiator of the project.

| Alternative | Why not |
|---|---|
| fail2ban | Regex on text logs, flat ban time, no ATT&CK enrichment, and it would need host firewall access from a container. |
| ELK / OpenSearch / Wazuh | Several gigabytes of RAM and a long start-up for a laptop lab. Great for production, poor for a 5-hour event with shared Wi-Fi. |
| Loki + Grafana | Lighter, but still three more containers to configure and explain. We expose `/metrics` so Prometheus and Grafana can be added later. |
| Nginx-only (`limit_req` + `deny`) | No memory across requests and no automatic escalation. |

## D5. How Sentinel applies a ban: blocklist file plus SIGHUP

**Chosen.** Sentinel writes a `geo` include file atomically and signals nginx. The reload is graceful and the control channel is a shared volume plus a shared PID namespace.

| Alternative | Why not |
|---|---|
| Mount `docker.sock` into Sentinel | Root-equivalent on the host. Unacceptable in a security project. |
| Host firewall (nftables/iptables) | Needs `NET_ADMIN` or host access, works differently on Docker Desktop, and breaks the "everything inside compose" portability. |
| Lua/OpenResty or njs shared-dict API | Faster than a reload but adds a custom nginx build. A reload every few seconds at most is fine here. |
| ModSecurity IP collections | Per-process persistence in v3 is awkward and gives no cross-component view. |

Trade-off accepted: the blocklist updates on a 2-second sweep, so a ban is not instantaneous. Bans become visible to nginx within a few seconds.

## D6. Rate limiting in nginx, not in the WAF rules

**Chosen.** `limit_req` is cheap, precise and well understood. Login endpoints get `5r/m` with burst 5; everything else `50r/s` with burst 200 and 100 connections per IP. In `detect` and `off` modes `limit_req_dry_run` logs but does not reject, which keeps the baseline honest.

| Alternative | Why not |
|---|---|
| CRS DoS rules | Not part of the default CRS 4 rule set, and heavier per request. |
| CAPTCHA/proof-of-work | Changes user experience, and the brief asks for rate limiting and automatic blocking. |

Limit: rate limits are per source IP. Attackers behind many IPs would need an upstream control.

## D7. Honeypot decoy paths

**Chosen.** A single rule that denies and tags requests for paths such as `/.env` or `/wp-login.php`. No legitimate Juice Shop user requests them, so precision is high, and Sentinel treats a hit as an immediate ban.

Alternative skipped: relying on the CRS scanner rules alone. Those catch known tool signatures, but a custom-header scanner would slip past, while the decoy catches the *behaviour*.

## D8. Virtual patches for specific Juice Shop flaws

**Chosen.** Three rules that fix real, documented flaws without changing app code: VPATCH-001 NoSQL operators in parameter names, VPATCH-002 JavaScript in the B2B order payload, VPATCH-003 poison-null-byte and sensitive-file access under `/ftp`. This is the stretch goal and the core "cannot patch this week" argument.

Skipped: virtual patches for every Juice Shop challenge. The app is intentionally full of holes, and a rule per challenge would overfit the lab instead of showing a method.

## D9. False-positive handling: scoped exclusions

**Chosen.** `ctl:ruleRemoveTargetByTag` limited to named targets (the JWT in the `token` cookie, `continueCode`, and the `Authorization` header). Never disable a whole rule.

Alternatives skipped: lowering the paranoia level globally, raising the threshold, or whitelisting URL paths. Each opens a broad hole to remove a narrow false positive.

## D10. TLS: private lab CA, TLS 1.2+ and AEAD ciphers only

**Chosen.** `make certs` creates a CA and a server certificate with SAN for `shield.local`, `waf`, `localhost` and `127.0.0.1`, so the test clients verify the certificate instead of disabling verification. HSTS and security headers are added at the edge.

Skipped: Let's Encrypt (no public hostname on a laptop), and self-signed certificates with `verify=False` (the exact anti-pattern a security panel would criticise).

## D11. Tech stack for Sentinel: Python standard library + SQLite

**Chosen.** No `pip install` in the image, which means no supply-chain surface and no dependency on venue Wi-Fi at build time. SQLite is enough for thousands of events and is persistent.

Skipped: Flask/FastAPI (extra dependency for six routes), PostgreSQL (extra container), a JS front-end build (the dashboard is one self-contained HTML file with escaping of all untrusted fields).

## D12. Orchestration: Docker Compose with a `lab` profile

**Chosen.** Works on any laptop; the attacker and client containers sit behind a profile so `make up` starts only the product, while `make attack` and `make benign` run the generators on demand with fixed IPs.

Skipped: Kubernetes (overkill, slower to start), VMs (heavier), running on the host (not reproducible).

## D13. Three modes: `on`, `detect`, `off`

**Chosen.** The same attack script runs in all modes. `off` proves the attacks are real (exploits succeed), `detect` supports tuning without blocking, `on` proves protection. Changing mode recreates the waf and sentinel containers, since Sentinel shares the WAF's PID namespace.

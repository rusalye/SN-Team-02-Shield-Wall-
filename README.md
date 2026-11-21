# Shield Wall — Web Application Defense Platform

A local, isolated hackathon lab for PS6: Shield Wall. It places Nginx + ModSecurity + OWASP CRS in front of OWASP Juice Shop, terminates TLS, adds narrow custom virtual-patching rules, and provides attack/benign replay plus a Streamlit event dashboard.

> Safety: run attack scripts only against your own local lab. Do not expose Juice Shop or this demo WAF to the public internet.

## Requirements
- Docker Engine + Docker Compose plugin
- OpenSSL
- Python 3.10+ on the host (for replay scripts)

## Quick start
```bash
cp .env.example .env
./scripts/generate_cert.sh
mkdir -p logs/waf data
docker compose pull
docker compose up -d --build
```
Open https://localhost:8443 (self-signed lab certificate) and dashboard http://localhost:8501.

The Juice Shop container is on an internal Docker network and has no host-published port. Only the WAF publishes 8443.

## Replay tests
```bash
python -m pip install requests
python scripts/benign_replay.py --insecure
python scripts/attack_replay.py --insecure
python scripts/summarize.py attack-results.csv benign-results.csv
```
The replay script is a starting test harness, not proof that every category is blocked. Juice Shop routes and CRS behavior vary by release/configuration. Verify each result and inspect WAF audit logs. Refine payloads against actual request paths until each attack class is reliably detected and benign pass rate is >=95%.

## Dashboard and event pipeline
`analytics/ingest.py` accepts normalized JSON events and appends them to `data/events.jsonl`. Example:
```bash
python analytics/ingest.py sample-event.json
```
The dashboard displays normalized events. ModSecurity audit logs are retained in `logs/waf`; a production-ready parser should be selected/configured for the exact audit-log format and image version. Do not treat the dashboard's normalized JSONL as an automatic parser for raw ModSecurity audit records.

## Configuration notes
- The official CRS image supports Nginx + ModSecurity and configurable TLS ports. This project uses the image's Nginx template mechanism.
- CRS is the primary WAF. Custom rules live separately in `waf/custom-rules.conf`.
- Login endpoint burst control is implemented as a ModSecurity IP-collection counter for POST requests to `/rest/user/login`. It counts requests, not verified failed passwords. The threshold is intentionally conservative for the demo and must be tuned against normal login behavior.
- The custom rule file is intentionally small and demonstrative. Validate syntax and false positives before the demo.
- Pin image versions for reproducibility. Update versions deliberately after regression tests.

## Acceptance checklist
- [ ] WAF container healthy
- [ ] Juice Shop reachable only through WAF
- [ ] TLS handshake negotiates TLS 1.2 or 1.3
- [ ] SQLi request blocked
- [ ] XSS request blocked
- [ ] Traversal request blocked
- [ ] Command injection request blocked
- [ ] Scanner UA blocked
- [ ] Login burst rate limited
- [ ] >=20 benign requests replayed
- [ ] Benign pass rate >=95%
- [ ] WAF and access logs retained
- [ ] Alert summary exported
- [ ] ATT&CK mapping and tuning notes included

## MITRE mapping
| Test class | Mapping |
|---|---|
| SQL injection / XSS / traversal / command injection | T1190 |
| Scanner User-Agent | T1595.002 |
| Login brute-force burst | T1110 |

## Important limitations before production
This is a hackathon lab, not a production-ready managed WAF. Use a trusted certificate, pin images by digest, configure trusted proxy boundaries, validate CRS tuning, implement durable rate-limit state and a tested WAF log parser, restrict dashboard access, add retention controls, and perform load/security testing before any real deployment.

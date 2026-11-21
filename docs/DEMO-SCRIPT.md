# Live demo script (6 minutes)

Preparation: open `http://127.0.0.1:9000/present` as the opening screen (it explains the design and fills in the before/after and scorecard as the demo runs); stack running, `make unban`, dashboard open at `http://127.0.0.1:9000` on a second window, terminal font large, `reports/` cleared with `make clean && make up`.

| Time | Do | Say |
|---|---|---|
| 0:00 | Slide or README diagram | "A legacy app that cannot be patched this week. We put a WAF in front, then close the loop with automatic response." |
| 0:30 | `make mode-off && docker compose run --rm attacker python attack_replay.py` | "Unprotected baseline. Attacks pass through and the login bypass and file read really work. This proves the lab is vulnerable and the test is honest." |
| 1:30 | `make mode-on && make unban && make benign` | "Now ShieldWall is on. Normal users: 27 realistic requests, all allowed. Our target was at least 95%." |
| 2:15 | `make attack` | "Same attack script. Every request is blocked: SQL injection, XSS, traversal, command injection, scanner agents, virtual patches. The brute force is throttled within a few attempts and the source is banned." |
| 3:15 | Dashboard | "Sentinel turned the WAF logs into this: attack types, mapped to ATT&CK, the active ban, the timeline. This is the alert summary the brief asks for." |
| 4:00 | `make report`, open `reports/alert_summary.md` | "Alerts by attack type with ATT&CK, CWE and CAPEC, ready for the SOC." |
| 4:30 | Show `waf/modsec/rules-before/00-honeypot.conf` and `20-virtual-patches.conf` | "Two things beyond the brief. Decoy paths that no real user requests: one hit and the source is banned. And virtual patches for three real Juice Shop flaws, which is the 'cannot patch' story." |
| 5:15 | Dashboard ban table (or `make attack` again, which is now answered with `blocked-ip`); point at the ban expiry and escalation (5 min, 30 min, 24 h) | "Bans escalate for repeat offenders and reload nginx gracefully, with no Docker socket mounted." |
| 5:45 | Close | "Reproducible with `make up && make demo`, 12 unit tests for the engine, full docs in the repo." |

## Interactive option (replaces minutes 2:15 to 4:00 if time allows)

Open the Attack Console at `http://127.0.0.1:8501`. Leave "Select all" on and press **Run selected attacks** to show the full set with live verdicts, or hand the mouse to a judge: untick everything, pick one class, or use "Craft your own request" to type a payload. Show the **Live defense view** tab updating as bans appear, then click **Unban all**.

## Fallbacks

* If the stack will not start: show the saved `reports/` files and dashboard screenshots, then walk through the architecture diagram.
* If a judge variant slips through: say so, show the rule that would catch it, add it live to `rules-before/20-virtual-patches.conf` and restart with `make mode-on`.
* If asked for a false positive: run `make fp` and explain the scoped-exclusion approach.

## Likely judge questions

| Question | Short answer |
|---|---|
| Why not just raise the threshold or lower paranoia? | That weakens every rule to fix one request. We exclude one target from one rule family instead. |
| How do you avoid banning real users behind a shared IP? | Bans need 20 weighted strikes in 2 minutes, escalate gradually, can be undone from the dashboard, and the allowlist covers trusted sources. Honeypots are the only instant ban. |
| What stops an attacker from using the dashboard? | It is bound to localhost, escapes all untrusted data, and the unban route supports a token. |
| Why a custom engine instead of a SIEM? | Laptop-sized, five-hour budget, and it understands ModSecurity records natively. `/metrics` lets you plug in Prometheus and Grafana later. |
| What can bypass this? | Anything the rules do not model, distributed low-rate attacks, and flaws exposed through legitimate-looking requests. A WAF is a compensating control; the app still needs patching. |
| Is Sentinel safe to run beside nginx? | It has read-only logs, no Docker socket, no inbound exposure except loopback, and validates every IP before writing the blocklist. |

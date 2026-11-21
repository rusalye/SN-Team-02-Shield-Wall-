"""Attack Console logic (no Streamlit imports, so it is unit-testable). The attack catalog is reused from
lab/tests/attack_replay.py, so the console and `make attack` can never drift apart."""
import json
import os
import sys

import requests

sys.path.insert(0, os.getenv("TESTS_DIR", "/tests"))
import attack_replay as ar                      # noqa: E402
from common import BASE, is_blocked, send, session, shield_action   # noqa: E402,F401

SENTINEL = os.getenv("SENTINEL_URL", "http://sentinel:9000").rstrip("/")
TOKEN = os.getenv("SENTINEL_TOKEN", "")

# attack class -> (stopping control, ATT&CK technique)
LAYER = {
    "SQL injection": ("CRS 942xxx rules + JSON body inspection", "T1190"),
    "Cross-site scripting": ("CRS 941xxx rules", "T1190"),
    "Path traversal": ("CRS 930xxx rules + VPATCH-003", "T1190"),
    "Command injection": ("CRS 932xxx rules", "T1190, T1059"),
    "Scanner user agent": ("CRS 913xxx scanner signatures", "T1595.002"),
    "Virtual patch": ("Custom virtual-patch rules", "T1190"),
    "Brute force": ("nginx rate limit + Sentinel auto-ban", "T1110"),
    "Honeypot probe": ("Decoy-path rule, instant ban", "T1595.003"),
}


def catalog():
    """One row per selectable attack: id, class, name, and the callable payload."""
    items = [dict(cls=c[0], name=c[1], case=c) for c in ar.CASES]
    items.append(dict(cls="Brute force", name="Login brute-force burst", case=None))
    items += [dict(cls="Honeypot probe", name=f"GET {p}", case=("Honeypot probe", f"GET {p}", "GET", p, {}, None))
              for p in ar.HONEYPOTS]
    for i, it in enumerate(items):
        it["id"] = i
    return items


def run_item(sess, item, attempts=40):
    """Execute one catalog item and return a flat result row."""
    if item["case"] is None:
        r = ar.brute_force(sess, attempts=attempts)
    else:
        r = ar.run_case(sess, item["case"])
    ctl, tech = LAYER.get(item["cls"], ("", ""))
    return dict(Class=item["cls"], Attack=item["name"], Status=r["status"],
                Verdict="BLOCKED" if r["blocked"] else "PASSED THROUGH",
                Exploited="YES" if r["exploited"] else "no", Control=ctl, ATTCK=tech,
                Note=r.get("note") or r.get("action", ""))


def ban_active(sess):
    """After an attack run the source should be auto-banned: a harmless request is now refused."""
    r, _ = send(sess, "GET", "/rest/admin/application-version")
    return not isinstance(r, Exception) and shield_action(r) == "blocked-ip"


def custom_request(sess, method, path, params=None, body="", ua=None):
    """Send one reviewer-supplied request to the WAF target (the host is fixed to the lab target)."""
    if not path.startswith("/"):
        path = "/" + path
    kw = {}
    if params:
        kw["params"] = params
    if body:
        kw.update(data=body, headers={"Content-Type": "application/json"})
    if ua:
        kw.setdefault("headers", {})["User-Agent"] = ua
    r, ms = send(sess, method, path, **kw)
    if isinstance(r, Exception):
        return dict(error=type(r).__name__)
    return dict(status=r.status_code, action=shield_action(r) or "(none)", blocked=is_blocked(r), ms=ms, body=r.text[:400])


def sentinel_get(path):
    try:
        return requests.get(SENTINEL + path, timeout=3).json()
    except (requests.RequestException, ValueError):
        return None


def sentinel_unban(ip=None):
    hdr = {"X-Token": TOKEN} if TOKEN else {}
    try:
        requests.post(SENTINEL + "/api/unban", data=json.dumps({"ip": ip} if ip else {"all": True}), headers=hdr, timeout=3)
        return True
    except requests.RequestException:
        return False

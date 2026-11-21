"""Shared helpers for the attack and benign replay scripts."""
import json
import os
import time

import requests
import urllib3

BASE = os.getenv("TARGET", "https://shield.local").rstrip("/")
CA = os.getenv("CA_BUNDLE", "/certs/ca.crt")
REPORT_DIR = os.getenv("REPORT_DIR", "/reports")
C = dict(red="\033[31m", green="\033[32m", yellow="\033[33m", dim="\033[2m", bold="\033[1m", end="\033[0m")
if not os.isatty(1):
    C = {k: "" for k in C}


def session(user_agent):
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent, "Accept": "*/*"})
    if os.path.exists(CA):
        s.verify = CA
    else:
        s.verify = False
        urllib3.disable_warnings()
    return s


def shield_action(resp):
    return resp.headers.get("X-Shield-Action", "")


def is_blocked(resp):
    return shield_action(resp).startswith(("blocked", "rate-limited"))


def send(s, method, path, **kw):
    t0 = time.time()
    try:
        r = s.request(method, BASE + path, timeout=15, allow_redirects=False, **kw)
        return r, int((time.time() - t0) * 1000)
    except requests.RequestException as exc:
        return exc, int((time.time() - t0) * 1000)


def save_report(label, payload):
    if os.path.isdir(REPORT_DIR) and label:
        path = os.path.join(REPORT_DIR, f"{label}.json")
        with open(path, "w") as fh:
            json.dump(payload, fh, indent=2)
        print(f"{C['dim']}report written to {path}{C['end']}")

#!/usr/bin/env python3
"""Benign replay: 28 normal requests (browse, search, register, login with correct credentials, shop).
Passes when at least 95% are NOT blocked by ShieldWall."""
import argparse
import random
import sys

from common import BASE, C, is_blocked, save_report, send, session, shield_action

UA = "Mozilla/5.0 (X11; Linux x86_64) ShieldWall-BenignReplay/1.0"
JSON = {"Content-Type": "application/json"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="")
    ap.add_argument("--threshold", type=float, default=95.0)
    args = ap.parse_args()

    s = session(UA)
    results = []
    email = f"user{random.randint(10000, 99999)}@shield.test"
    password = "ShieldTest!2024"
    state = {}

    def step(name, method, path, **kw):
        r, ms = send(s, method, path, **kw)
        ok = not isinstance(r, Exception) and not is_blocked(r)
        code = 0 if isinstance(r, Exception) else r.status_code
        results.append(dict(name=name, status=code, allowed=ok, action="" if isinstance(r, Exception) else shield_action(r), ms=ms))
        print(f"{name:<38} {code:>3}  {C['green'] + 'ALLOWED' if ok else C['red'] + 'BLOCKED'}{C['end']}")
        return None if isinstance(r, Exception) else r

    print(f"{C['bold']}ShieldWall benign replay -> {BASE}{C['end']}\n")
    step("Home page", "GET", "/")
    step("robots.txt", "GET", "/robots.txt")
    step("i18n bundle", "GET", "/assets/i18n/en.json")
    step("Application version", "GET", "/rest/admin/application-version")
    step("Application configuration", "GET", "/rest/admin/application-configuration")
    step("Product catalogue", "GET", "/api/Products")
    for term in ("apple", "banana", "orange juice", "lemon", "carrot", ""):
        step(f"Search '{term}'", "GET", "/rest/products/search", params={"q": term})
    step("Product detail", "GET", "/api/Products/1")
    step("Product reviews", "GET", "/rest/products/1/reviews")
    step("Languages", "GET", "/rest/languages")
    step("Socket.io polling handshake", "GET", "/socket.io/?EIO=4&transport=polling")
    step("Captcha", "GET", "/rest/captcha/")
    step("Register account", "POST", "/api/Users",
         data=f'{{"email":"{email}","password":"{password}","passwordRepeat":"{password}"}}', headers=JSON)
    r = step("Login (correct credentials)", "POST", "/rest/user/login", data=f'{{"email":"{email}","password":"{password}"}}', headers=JSON)
    try:
        auth = r.json()["authentication"]
        state = dict(h={"Authorization": f"Bearer {auth['token']}"}, bid=auth["bid"])
    except Exception:
        state = dict(h={}, bid=1)
    step("Who am I", "GET", "/rest/user/whoami", headers=state["h"])
    step("View basket", "GET", f"/rest/basket/{state['bid']}", headers=state["h"])
    step("Add item to basket", "POST", "/api/BasketItems",
         data=f'{{"ProductId":1,"BasketId":"{state["bid"]}","quantity":1}}', headers={**JSON, **state["h"]})
    step("View basket again", "GET", f"/rest/basket/{state['bid']}", headers=state["h"])
    step("Post a review", "PUT", "/rest/products/1/reviews",
         data=f'{{"message":"Tasty juice, would buy again.","author":"{email}"}}', headers={**JSON, **state["h"]})
    step("Order history", "GET", "/rest/order-history", headers=state["h"])
    step("Deluxe membership info", "GET", "/rest/deluxe-membership", headers=state["h"])
    step("Stock quantities", "GET", "/api/Quantitys/", headers=state["h"])

    allowed = sum(r["allowed"] for r in results)
    pct = 100.0 * allowed / len(results)
    print(f"\nAllowed {allowed}/{len(results)} ({pct:.1f}%), required >= {args.threshold}%")
    for r in results:
        if not r["allowed"]:
            print(f"{C['yellow']}false positive:{C['end']} {r['name']}  -> run `make fp` to see which CRS rules fired")
    save_report(args.label, dict(target=BASE, allowed=allowed, total=len(results), allowed_pct=pct, results=results))
    sys.exit(0 if pct >= args.threshold else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Run only against the local Shield Wall lab."""
import argparse, csv, time
from datetime import datetime, timezone
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

CASES = [
    ("sqli", "GET", "/rest/products/search", {"q": "' OR 1=1--"}, None, "T1190"),
    ("xss", "GET", "/", {"q": "<script>alert(1)</script>"}, None, "T1190"),
    ("path_traversal", "GET", "/", {"file": "../../etc/passwd"}, None, "T1190"),
    ("command_injection", "GET", "/", {"cmd": ";id"}, None, "T1190"),
    ("scanner_ua", "GET", "/", None, {"User-Agent": "sqlmap/1.8"}, "T1595.002"),
    ("login_burst", "POST", "/rest/user/login", None, {"Content-Type":"application/json"}, "T1110"),
]

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--base", default="https://localhost:8443")
    p.add_argument("--out", default="attack-results.csv")
    p.add_argument("--insecure", action="store_true", help="Use only with the local self-signed lab certificate")
    a=p.parse_args()
    rows=[]
    for category, method, path, params, headers, mitre in CASES:
        reps = 12 if category == "login_burst" else 1
        for i in range(reps):
            h = dict(headers or {})
            if category == "login_burst":
                h["Content-Type"]="application/json"
                body={"email":"demo@invalid.local","password":f"wrong-{i}"}
                r=requests.post(a.base+path,json=body,headers=h,verify=not a.insecure,timeout=10)
            else:
                r=requests.request(method,a.base+path,params=params,headers=h or {},verify=not a.insecure,timeout=10)
            rows.append({
                "timestamp":datetime.now(timezone.utc).isoformat(),
                "category":category,"method":method,"path":path,
                "status":r.status_code,"blocked":r.status_code in (403,429),
                "mitre":mitre
            })
            print(f"{category:18} HTTP {r.status_code}")
            time.sleep(.15)
    with open(a.out,"w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    print(f"Saved {len(rows)} results to {a.out}")

if __name__=="__main__": main()

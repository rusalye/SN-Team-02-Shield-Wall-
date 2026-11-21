#!/usr/bin/env python3
"""Generate >=20 ordinary local requests through the protected gateway."""
import argparse, csv, time, requests
from datetime import datetime, timezone
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

PATHS = [
 "/", "/robots.txt", "/favicon.ico", "/api/Challenges",
 "/rest/products/search?q=apple", "/rest/products/search?q=banana",
 "/rest/products/search?q=juice", "/rest/products/search?q=water",
 "/rest/products/1", "/rest/products/2", "/rest/products/3",
 "/rest/products/4", "/rest/products/5", "/rest/products/6",
 "/rest/products/7", "/rest/products/8", "/rest/products/9",
 "/rest/products/10", "/rest/products/11", "/rest/products/12",
 "/rest/languages", "/api/Quantitys"
]
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--base",default="https://localhost:8443")
    p.add_argument("--out",default="benign-results.csv")
    p.add_argument("--insecure",action="store_true")
    a=p.parse_args()
    rows=[]
    for path in PATHS:
        try:
            r=requests.get(a.base+path,verify=not a.insecure,timeout=10)
            status=r.status_code
        except requests.RequestException:
            status=0
        rows.append({"timestamp":datetime.now(timezone.utc).isoformat(),"path":path,"status":status,"allowed":200<=status<400})
        print(f"{path:42} HTTP {status}")
        time.sleep(.08)
    with open(a.out,"w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
    print(f"Saved {len(rows)} benign results to {a.out}")
if __name__=="__main__":main()

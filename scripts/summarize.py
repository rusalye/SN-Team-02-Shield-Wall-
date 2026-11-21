#!/usr/bin/env python3
import csv, json, sys
from collections import Counter
attack, benign = sys.argv[1:3]
with open(attack, newline="") as f: a=list(csv.DictReader(f))
with open(benign, newline="") as f: b=list(csv.DictReader(f))
blocked=sum(x["blocked"].lower()=="true" for x in a)
allowed=sum(x["allowed"].lower()=="true" for x in b)
report={
 "attack_requests":len(a),"attack_blocked":blocked,
 "attack_block_rate_pct":round(100*blocked/len(a),2) if a else 0,
 "benign_requests":len(b),"benign_allowed":allowed,
 "benign_pass_rate_pct":round(100*allowed/len(b),2) if b else 0,
 "attack_categories":dict(Counter(x["category"] for x in a))
}
print(json.dumps(report,indent=2))
with open("acceptance-summary.json","w") as f: json.dump(report,f,indent=2)

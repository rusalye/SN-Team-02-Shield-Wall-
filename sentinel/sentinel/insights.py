"""Read-side analytics: dashboard summary, alert report, ATT&CK Navigator layer, Prometheus metrics."""
import json
import time
from collections import Counter

from . import attackmap, config

TECHNIQUE_NAMES = {
    "T1190": "Exploit Public-Facing Application", "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1595.003": "Active Scanning: Wordlist Scanning", "T1110": "Brute Force",
    "T1059": "Command and Scripting Interpreter", "T1498": "Network Denial of Service",
}


def summary(store, engine):
    events = store.recent(5000)
    by = {}
    for e in events:
        b = by.setdefault(e["ptype"], dict(count=0, blocked=0, ips=set(), rules=Counter()))
        b["count"] += 1
        b["blocked"] += 1 if e["blocked"] else 0
        b["ips"].add(e["ip"])
        b["rules"].update(e["rules"])
    by_type = []
    for t, b in sorted(by.items(), key=lambda kv: -kv[1]["count"]):
        i = attackmap.info(t)
        by_type.append(dict(type=t, label=i["label"], count=b["count"], blocked=b["blocked"], ips=len(b["ips"]),
                            attack=i["attack"], cwe=i["cwe"], capec=i["capec"],
                            top_rules=[r for r, _ in b["rules"].most_common(4)]))
    total, blocked = store.traffic_totals()
    techniques = Counter(t for e in events for t in e["techniques"])
    top_ips = Counter(e["ip"] for e in events)
    top_rules = Counter(r for e in events for r in e["rules"])
    bans = store.bans(active_only=True)
    return dict(
        mode=config.MODE, uptime=int(time.time() - engine.started),
        totals=dict(requests=total, blocked=blocked, events=len(events),
                    blocked_events=sum(1 for e in events if e["blocked"]), active_bans=len(bans)),
        by_type=by_type,
        top_ips=[dict(ip=i, count=c, banned=i in engine.banned) for i, c in top_ips.most_common(6)],
        top_rules=[dict(id=r, count=c, msg=engine.rulemap.get(r, "")) for r, c in top_rules.most_common(8)],
        techniques=[dict(id=t, name=TECHNIQUE_NAMES.get(t, ""), count=c) for t, c in techniques.most_common()],
        timeline=store.traffic_series(30), bans=bans)


def report_md(store, engine):
    s = summary(store, engine)
    t = s["totals"]
    rate = (100.0 * t["blocked"] / t["requests"]) if t["requests"] else 0.0
    lines = [
        "# ShieldWall alert summary", "",
        f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"- Mode: **{s['mode']}**",
        f"- Requests seen: {t['requests']}  |  blocked at edge: {t['blocked']} ({rate:.1f}%)",
        f"- Attack events recorded: {t['events']}  |  active bans: {t['active_bans']}", "",
        "## Alerts by attack type", "",
        "| Attack type | Events | Blocked | Sources | ATT&CK | CWE | CAPEC | Top rule IDs |",
        "|---|---:|---:|---:|---|---|---|---|",
    ]
    for r in s["by_type"]:
        lines.append(f"| {r['label']} | {r['count']} | {r['blocked']} | {r['ips']} | {', '.join(r['attack'])} | "
                     f"{r['cwe'] or '-'} | {r['capec'] or '-'} | {', '.join(r['top_rules']) or '-'} |")
    lines += ["", "## Top triggered rules", "", "| Rule ID | Hits | Message |", "|---|---:|---|"]
    lines += [f"| {r['id']} | {r['count']} | {r['msg']} |" for r in s["top_rules"]]
    lines += ["", "## Automatic bans", "", "| Source IP | Offense # | Reason | Banned until |", "|---|---:|---|---|"]
    lines += [f"| {b['ip']} | {b['offenses']} | {b['reason']} | {time.strftime('%H:%M:%S', time.localtime(b['until']))} |"
              for b in s["bans"]]
    return "\n".join(lines) + "\n"


def navigator_layer(store, engine):
    s = summary(store, engine)
    return dict(
        name="ShieldWall observed techniques", domain="enterprise-attack",
        versions=dict(attack="16", navigator="5.1.0", layer="4.5"),
        description="Generated from live WAF events. Confirm ATT&CK version before publishing.",
        gradient=dict(colors=["#ffe0b2", "#d32f2f"], minValue=0, maxValue=max([t["count"] for t in s["techniques"]] or [1])),
        techniques=[dict(techniqueID=t["id"], score=t["count"], comment=f"{t['count']} events observed and handled by ShieldWall")
                    for t in s["techniques"]])


def metrics(store, engine):
    s = summary(store, engine)
    out = ["# TYPE shieldwall_requests_total counter", f"shieldwall_requests_total {s['totals']['requests']}",
           "# TYPE shieldwall_blocked_total counter", f"shieldwall_blocked_total {s['totals']['blocked']}",
           "# TYPE shieldwall_active_bans gauge", f"shieldwall_active_bans {s['totals']['active_bans']}",
           "# TYPE shieldwall_attack_events gauge"]
    out += [f'shieldwall_attack_events{{type="{r["type"]}"}} {r["count"]}' for r in s["by_type"]]
    return "\n".join(out) + "\n"

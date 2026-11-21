"""Adaptive response engine: turns WAF and rate-limit events into strikes, bans and alerts."""
import json
import logging
import re
import threading
import time
from collections import defaultdict, deque

from . import attackmap, config, nginx_ctl

log = logging.getLogger("sentinel.engine")
SCORE_RE = re.compile(r"Total Score:\s*(\d+)")


def parse_audit(line):
    try:
        tx = json.loads(line)["transaction"]
    except (ValueError, KeyError, TypeError):
        return None
    req, resp = tx.get("request") or {}, tx.get("response") or {}
    headers = {str(k).lower(): v for k, v in (req.get("headers") or {}).items()}
    rules, total_score = [], None
    for m in tx.get("messages") or []:
        d = m.get("details") or {}
        sev = str(d.get("severity", ""))
        rid = str(d.get("ruleId", ""))
        text = m.get("message", "")
        rules.append(dict(id=rid, sev=int(sev) if sev.isdigit() else 5, tags=d.get("tags") or [], text=text))
        if rid == "949110":
            hit = SCORE_RE.search(text)
            total_score = int(hit.group(1)) if hit else total_score
    if not rules:
        return None

    primary, types, techniques, pts = attackmap.classify(rules)
    status = int(resp.get("http_code") or 0)
    visible = [r for r in rules if not r["id"].startswith(attackmap.EVALUATION_PREFIXES)]
    return dict(
        ts=time.time(), ip=tx.get("client_ip", "?"), method=req.get("method", ""), uri=(req.get("uri") or "")[:500],
        ua=str(headers.get("user-agent", ""))[:200], status=status, uid=tx.get("unique_id", ""),
        rules=[r["id"] for r in visible], rulemap={r["id"]: r["text"][:120] for r in visible},
        types=types, ptype=primary, techniques=techniques, score=total_score if total_score is not None else pts,
        blocked=status == 403, action="blocked" if status == 403 else "detected",
        msg=(visible[0]["text"] if visible else "")[:160],
        honeypot="honeypot" in types,
    )


class Engine:
    def __init__(self, store):
        self.store = store
        self.lock = threading.RLock()
        self.strikes = defaultdict(deque)
        self.banned = {b["ip"]: b["until"] for b in store.bans(active_only=True) if b["until"] > time.time()}
        self.rulemap = {}
        self.tbuf = defaultdict(lambda: [0, 0])
        self.last_event = {}
        self.dirty = True
        self.started = time.time()

    # ------------------------------------------------------------ ingestion
    def on_audit(self, line):
        ev = parse_audit(line)
        if not ev:
            return
        with self.lock:
            self.rulemap.update(ev.pop("rulemap"))
            honeypot = ev.pop("honeypot")
            self.store.add_event(ev)
            if ev["blocked"]:
                self._strike(ev["ip"], config.BAN_STRIKES if honeypot else 1.0,
                             f"{attackmap.info(ev['ptype'])['label']} blocked")

    def on_access(self, line):
        try:
            rec = json.loads(line)
        except ValueError:
            return
        ip, status, shield = rec.get("ip", "?"), int(rec.get("status", 0)), rec.get("shield", "")
        path = (rec.get("uri") or "").split("?")[0]
        now = time.time()
        with self.lock:
            bucket = self.tbuf[int(now // 60)]
            bucket[0] += 1
            bucket[1] += 1 if shield else 0
            login = path in config.LOGIN_PATHS
            if status == 429 and shield == "rate-limited":
                self._soft_event(ip, rec, "brute-force" if login else "rate-limit", "rate-limited", 1.0 if login else 0.5)
            elif status == 401 and path == "/rest/user/login":
                self._soft_event(ip, rec, "brute-force", "observed", 0.5)

    def _soft_event(self, ip, rec, atype, action, weight):
        key = (ip, atype, action)
        now = time.time()
        if now - self.last_event.get(key, 0) >= 1.0:        # cap event volume to ~1/s per source and type
            self.last_event[key] = now
            info = attackmap.info(atype)
            self.store.add_event(dict(
                ts=now, ip=ip, method=rec.get("method", ""), uri=(rec.get("uri") or "")[:500], ua=(rec.get("ua") or "")[:200],
                status=int(rec.get("status", 0)), uid=rec.get("rid", ""), rules=[], types=[atype], ptype=atype,
                techniques=info["attack"], score=0, action=action, blocked=action == "rate-limited",
                msg="Login attempt rate-limited" if action == "rate-limited" else "Failed login attempt"))
        self._strike(ip, weight, info_label(atype))

    # ------------------------------------------------------------ ban logic
    def _strike(self, ip, weight, reason):
        if config.MODE != "on" or ip in config.ALLOWLIST or ip in self.banned:
            return
        now = time.time()
        q = self.strikes[ip]
        q.append((now, weight))
        while q and now - q[0][0] > config.STRIKE_WINDOW:
            q.popleft()
        if sum(w for _, w in q) >= config.BAN_STRIKES:
            self._ban(ip, reason)

    def _ban(self, ip, reason):
        offenses = self.store.offenses(ip) + 1
        step = config.BAN_STEPS[min(offenses - 1, len(config.BAN_STEPS) - 1)]
        now = time.time()
        self.banned[ip] = now + step
        self.store.upsert_ban(ip, now, now + step, offenses, reason)
        self.strikes.pop(ip, None)
        self.dirty = True
        log.warning("BAN %s for %ss (offense #%d): %s", ip, step, offenses, reason)

    def unban(self, ip=None):
        with self.lock:
            if ip:
                self.banned.pop(ip, None)
                self.store.deactivate_ban(ip)
            else:
                self.banned.clear()
                self.strikes.clear()
                self.store.deactivate_ban()
            self.dirty = True

    def sweep(self):
        """Periodic: expire bans, flush traffic buckets, push the blocklist to nginx when it changed."""
        with self.lock:
            now = time.time()
            for ip in [i for i, until in self.banned.items() if until <= now]:
                self.banned.pop(ip)
                self.store.deactivate_ban(ip)
                self.dirty = True
            flush, self.tbuf = self.tbuf, defaultdict(lambda: [0, 0])
            for minute, (total, blocked) in flush.items():
                self.store.traffic_add(minute, total, blocked)
            if self.dirty:
                self.dirty = False
                try:
                    nginx_ctl.apply_blocklist(config.BLOCKLIST, set(self.banned) if config.MODE == "on" else set())
                except OSError as exc:
                    log.error("cannot write blocklist: %s", exc)
                    self.dirty = True


def info_label(atype):
    return attackmap.info(atype)["label"]

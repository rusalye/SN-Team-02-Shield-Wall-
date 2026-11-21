import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, ip TEXT, method TEXT, uri TEXT, ua TEXT,
  status INTEGER, uid TEXT, rules TEXT, types TEXT, ptype TEXT, techniques TEXT,
  score INTEGER, action TEXT, blocked INTEGER, msg TEXT);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_ip ON events(ip);
CREATE TABLE IF NOT EXISTS bans(
  ip TEXT PRIMARY KEY, since REAL, until REAL, offenses INTEGER, reason TEXT, active INTEGER);
CREATE TABLE IF NOT EXISTS traffic(minute INTEGER PRIMARY KEY, total INTEGER, blocked INTEGER);
CREATE TABLE IF NOT EXISTS offsets(path TEXT PRIMARY KEY, inode INTEGER, off INTEGER);
"""


class Store:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.db.executescript(SCHEMA)
            self.db.commit()

    def _run(self, sql, args=(), write=False):
        with self.lock:
            cur = self.db.execute(sql, args)
            if write:
                self.db.commit()
            return cur.fetchall() if not write else None

    # ---- events ----
    def add_event(self, e):
        self._run(
            "INSERT INTO events(ts,ip,method,uri,ua,status,uid,rules,types,ptype,techniques,score,action,blocked,msg)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (e["ts"], e["ip"], e["method"], e["uri"], e["ua"], e["status"], e["uid"],
             json.dumps(e["rules"]), json.dumps(e["types"]), e["ptype"], json.dumps(e["techniques"]),
             e["score"], e["action"], int(e["blocked"]), e["msg"]), write=True)

    def recent(self, limit=200, ip=None, blocked_only=False):
        sql, args = "SELECT * FROM events", []
        where = []
        if ip:
            where.append("ip=?"); args.append(ip)
        if blocked_only:
            where.append("blocked=1")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        out = []
        for r in self._run(sql, args):
            d = dict(r)
            for k in ("rules", "types", "techniques"):
                d[k] = json.loads(d[k] or "[]")
            d["blocked"] = bool(d["blocked"])
            out.append(d)
        return out

    # ---- bans ----
    def offenses(self, ip):
        r = self._run("SELECT offenses FROM bans WHERE ip=?", (ip,))
        return r[0]["offenses"] if r else 0

    def upsert_ban(self, ip, since, until, offenses, reason):
        self._run("INSERT OR REPLACE INTO bans VALUES(?,?,?,?,?,1)", (ip, since, until, offenses, reason), write=True)

    def deactivate_ban(self, ip=None):
        if ip:
            self._run("UPDATE bans SET active=0 WHERE ip=?", (ip,), write=True)
        else:
            self._run("UPDATE bans SET active=0", write=True)

    def bans(self, active_only=False):
        sql = "SELECT * FROM bans" + (" WHERE active=1" if active_only else "") + " ORDER BY since DESC"
        return [dict(r) for r in self._run(sql)]

    # ---- traffic buckets ----
    def traffic_add(self, minute, total, blocked):
        self._run("INSERT INTO traffic VALUES(?,?,?) ON CONFLICT(minute) DO UPDATE SET "
                  "total=total+excluded.total, blocked=blocked+excluded.blocked", (minute, total, blocked), write=True)

    def traffic_series(self, minutes=30):
        now = int(time.time() // 60)
        rows = {r["minute"]: r for r in self._run("SELECT * FROM traffic WHERE minute>?", (now - minutes,))}
        return [dict(t=m * 60, total=rows[m]["total"] if m in rows else 0,
                     blocked=rows[m]["blocked"] if m in rows else 0) for m in range(now - minutes + 1, now + 1)]

    def traffic_totals(self):
        r = self._run("SELECT COALESCE(SUM(total),0) t, COALESCE(SUM(blocked),0) b FROM traffic")[0]
        return r["t"], r["b"]

    # ---- tail offsets (survive restarts without double counting) ----
    def get_offset(self, path):
        r = self._run("SELECT inode, off FROM offsets WHERE path=?", (path,))
        return (r[0]["inode"], r[0]["off"]) if r else None

    def set_offset(self, path, inode, off):
        self._run("INSERT OR REPLACE INTO offsets VALUES(?,?,?)", (path, inode, off), write=True)

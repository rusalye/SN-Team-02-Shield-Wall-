"""Offline unit tests for Sentinel (no Docker needed): `make test`."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
_TMP = tempfile.mkdtemp()
os.environ.update(DB_PATH=os.path.join(_TMP, "t.db"), BLOCKLIST=os.path.join(_TMP, "bl.conf"),
                  BAN_STRIKES="20", SHIELD_MODE="on", ALLOWLIST="127.0.0.1")

from sentinel import attackmap, config, engine, store  # noqa: E402

SQLI = [("942100", "SQL Injection", 2, ["attack-sqli"]), ("949110", "Inbound Anomaly Score Exceeded (Total Score: 10)", 2, [])]
HONEYPOT = [("1000010", "honeypot", 2, ["shieldwall/honeypot", "attack.t1595"])]
VPATCH = [("1000200", "VPATCH-001", 2, ["shieldwall/vpatch", "CWE-943"])]


def audit(ip, uri, rules, code=403):
    msgs = [{"message": m, "details": {"ruleId": r, "severity": str(sv), "tags": tg}} for r, m, sv, tg in rules]
    return json.dumps({"transaction": {"client_ip": ip, "unique_id": "u", "request": {"method": "GET", "uri": uri, "headers": {"User-Agent": "t"}},
                                       "response": {"http_code": code}, "messages": msgs}})


class ClassificationTests(unittest.TestCase):
    def test_sqli_is_classified_and_mapped(self):
        ev = engine.parse_audit(audit("10.0.0.1", "/q", SQLI))
        self.assertEqual(ev["ptype"], "sqli")
        self.assertEqual(ev["techniques"], ["T1190"])
        self.assertEqual(ev["score"], 10)
        self.assertTrue(ev["blocked"])

    def test_evaluation_rules_are_not_attacks(self):
        ev = engine.parse_audit(audit("10.0.0.1", "/q", SQLI))
        self.assertNotIn("949110", ev["rules"])

    def test_custom_rules_outrank_crs(self):
        self.assertEqual(engine.parse_audit(audit("10.0.0.1", "/.env", HONEYPOT))["ptype"], "honeypot")
        self.assertEqual(engine.parse_audit(audit("10.0.0.1", "/r", VPATCH))["ptype"], "virtual-patch")

    def test_detect_mode_status_is_not_blocked(self):
        self.assertFalse(engine.parse_audit(audit("10.0.0.1", "/q", SQLI, code=200))["blocked"])

    def test_garbage_line_is_ignored(self):
        self.assertIsNone(engine.parse_audit("not json"))

    def test_every_type_has_mapping(self):
        for t, meta in attackmap.TYPES.items():
            self.assertTrue(meta["attack"], t)


class BanTests(unittest.TestCase):
    def setUp(self):
        config.MODE = "on"
        self.store = store.Store(os.path.join(tempfile.mkdtemp(), "s.db"))
        self.eng = engine.Engine(self.store)

    def test_ban_at_threshold_not_before(self):
        for _ in range(19):
            self.eng.on_audit(audit("10.0.0.9", "/q", SQLI))
        self.assertNotIn("10.0.0.9", self.eng.banned)
        self.eng.on_audit(audit("10.0.0.9", "/q", SQLI))
        self.assertIn("10.0.0.9", self.eng.banned)

    def test_honeypot_bans_on_first_hit(self):
        self.eng.on_audit(audit("10.0.0.7", "/.env", HONEYPOT))
        self.assertIn("10.0.0.7", self.eng.banned)

    def test_allowlisted_ip_is_never_banned(self):
        self.eng.on_audit(audit("127.0.0.1", "/.env", HONEYPOT))
        self.assertNotIn("127.0.0.1", self.eng.banned)

    def test_detect_mode_never_bans(self):
        config.MODE = "detect"
        self.eng.on_audit(audit("10.0.0.5", "/.env", HONEYPOT))
        self.assertNotIn("10.0.0.5", self.eng.banned)

    def test_repeat_offender_escalates(self):
        self.eng.on_audit(audit("10.0.0.3", "/.env", HONEYPOT))
        first = self.eng.banned["10.0.0.3"]
        self.eng.unban("10.0.0.3")
        self.store.upsert_ban("10.0.0.3", 0, 0, 1, "seed")          # one prior offense on record
        self.eng.on_audit(audit("10.0.0.3", "/.env", HONEYPOT))
        self.assertGreater(self.eng.banned["10.0.0.3"] - first, 1000)   # 30 min step vs 5 min

    def test_blocklist_file_is_valid_and_sanitised(self):
        from sentinel import nginx_ctl
        path = os.path.join(tempfile.mkdtemp(), "bl.conf")
        nginx_ctl.apply_blocklist(path, {"10.0.0.1", "evil;rm -rf /", "::1"})
        body = open(path).read()
        self.assertIn("10.0.0.1 1;", body)
        self.assertNotIn("evil", body)


if __name__ == "__main__":
    unittest.main()

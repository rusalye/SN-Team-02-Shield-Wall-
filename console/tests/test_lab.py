"""Offline tests for the console logic against a fake WAF: `make test`."""
import os, sys, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(__file__)
os.environ.update(TESTS_DIR=os.path.join(HERE, "..", "..", "lab", "tests"), CA_BUNDLE="/nonexistent")


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _go(self):
        bad = any(x in self.path.lower() for x in ("union", "script", "etc", "cat", "%2e", ".env", "whoami", "wget", "or%201"))
        self.send_response(403 if bad else 200)
        if bad: self.send_header("X-Shield-Action", "blocked-waf")
        self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    do_GET = do_POST = do_PUT = do_PATCH = _go


srv = HTTPServer(("127.0.0.1", 0), Fake)
threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ["TARGET"] = f"http://127.0.0.1:{srv.server_port}"
sys.path.insert(0, os.path.join(HERE, ".."))
import lab  # noqa: E402


class LabTests(unittest.TestCase):
    def test_catalog_matches_replay(self):
        items = lab.catalog()
        self.assertEqual(len(items), 20)                       # 16 payloads + brute force + 3 honeypots
        self.assertEqual({i["cls"] for i in items}, set(lab.LAYER))
        self.assertEqual(sorted(i["id"] for i in items), list(range(20)))

    def test_run_item_flags_blocked(self):
        s = lab.session("t")
        row = lab.run_item(s, next(i for i in lab.catalog() if i["cls"] == "Honeypot probe"))
        self.assertEqual(row["Verdict"], "BLOCKED")
        self.assertEqual(row["ATTCK"], "T1595.003")

    def test_custom_request(self):
        s = lab.session("t")
        self.assertTrue(lab.custom_request(s, "GET", "x", {"q": "<script>"})["blocked"])
        self.assertFalse(lab.custom_request(s, "GET", "/", None)["blocked"])

    def test_sentinel_unreachable_is_handled(self):
        lab.SENTINEL = "http://127.0.0.1:1"
        self.assertIsNone(lab.sentinel_get("/api/summary"))
        self.assertFalse(lab.sentinel_unban())


if __name__ == "__main__":
    unittest.main()

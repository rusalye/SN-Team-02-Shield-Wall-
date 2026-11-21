import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import config, insights

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
STATIC = os.path.join(STATIC_DIR, "dashboard.html")
EVIDENCE = ("1_attack_baseline_waf_off", "2_benign_waf_on", "3_attack_waf_on")


def load_evidence():
    """Replay reports written by `make demo`; missing files are simply absent."""
    out = {}
    for name in EVIDENCE:
        try:
            with open(os.path.join(config.REPORT_DIR, name + ".json")) as fh:
                out[name] = json.load(fh)
        except (OSError, ValueError):
            pass
    return out


def make_server(store, engine):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Sentinel"

        def log_message(self, *args):
            pass

        def _send(self, code, body, ctype="application/json"):
            if isinstance(body, (dict, list)):
                body = json.dumps(body)
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            url = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            p = url.path
            if p == "/":
                with open(STATIC, "rb") as fh:
                    return self._send(200, fh.read(), "text/html")
            if p in ("/alerts", "/attack-layer", "/metrics-view"):
                with open(os.path.join(STATIC_DIR, "insights.html"), "rb") as fh:
                    return self._send(200, fh.read(), "text/html")
            if p == "/present":
                with open(os.path.join(STATIC_DIR, "presenter.html"), "rb") as fh:
                    return self._send(200, fh.read(), "text/html")
            if p == "/api/evidence":
                return self._send(200, load_evidence())
            if p == "/healthz":
                return self._send(200, "ok", "text/plain")
            if p == "/api/summary":
                return self._send(200, insights.summary(store, engine))
            if p == "/api/events":
                return self._send(200, store.recent(min(int(q.get("limit", 50)), 1000), q.get("ip"), q.get("blocked") == "1"))
            if p == "/api/bans":
                return self._send(200, store.bans(active_only=True))
            if p == "/api/navigator-layer":
                return self._send(200, insights.navigator_layer(store, engine))
            if p == "/report.md":
                return self._send(200, insights.report_md(store, engine), "text/markdown")
            if p == "/metrics":
                return self._send(200, insights.metrics(store, engine), "text/plain")
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if config.TOKEN and self.headers.get("X-Token") != config.TOKEN:
                return self._send(401, {"error": "unauthorized"})
            if urlparse(self.path).path != "/api/unban":
                return self._send(404, {"error": "not found"})
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            except ValueError:
                return self._send(400, {"error": "invalid json"})
            engine.unban(None if body.get("all") else body.get("ip"))
            self._send(200, {"ok": True})

    return ThreadingHTTPServer(("0.0.0.0", config.PORT), Handler)

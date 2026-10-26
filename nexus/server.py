"""Local control surface: one process, zero dependencies, binds localhost.

GET endpoints are open (local-only by binding); POST run is token-guarded.

  /                   dashboard/index.html (Arabic RTL control panel)
  /health             {"ok": true}
  /api/status         run state + meters snapshot + license status
  /api/dashboard-data combined JSON the dashboard consumes
  /api/metrics        Prometheus text format (scrape directly)
  /api/report         latest markdown audit receipt
  POST /api/run?token=…  {"manifest": "path"} or {"manifest_dict": {...}}
"""
import json
import os
import secrets
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import __version__, license as license_mod, meters as meters_mod
from . import runner, storage, transport

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MAX_BODY = 65536
_TOKEN_UNSET = object()


class ControlServer(object):
    """Owns ledger + meters + run state; the HTTP layer stays dumb."""

    def __init__(self, ledger_path="radar-ledger.db", relay_pool=None,
                 meters=None):
        self.ledger = storage.Ledger(ledger_path)
        self.meters = meters or meters_mod.Meters()
        self.relays = relay_pool or transport.RelayPool()
        self.lock = threading.Lock()
        self.state = {"running": False, "started": None, "summary": None,
                      "error": None}
        self.token = secrets.token_hex(16)

    # ------------------------------------------------------------ run flows
    def start_run(self, manifest_path, max_pages=runner.MAX_PAGES_DEFAULT,
                  workers=None, deep_hosts=()):
        with self.lock:
            if self.state["running"]:
                return {"ok": False, "err": "already running"}
            self.state.update(running=True, started=time.time(),
                              summary=None, error=None)
        th = threading.Thread(target=self._work, daemon=True,
                              args=(manifest_path, max_pages, workers,
                                    deep_hosts))
        th.start()
        return {"ok": True, "state": "started"}

    def _work(self, manifest_path, max_pages, workers, deep_hosts):
        try:
            orch = runner.Orchestrator(manifest_path, self.ledger,
                                       relay_pool=self.relays,
                                       deep_hosts=deep_hosts,
                                       meters=self.meters)
            if workers:
                summary = orch.run_concurrent(workers=workers,
                                              max_pages=max_pages)
            else:
                summary = orch.run(max_pages=max_pages)
            self.meters.set_gauge("radar_ledger_rows", self.ledger.count())
            with self.lock:
                self.state.update(running=False, summary=summary, error=None)
        except Exception as e:                      # run failures are data too
            with self.lock:
                self.state.update(running=False, summary=None,
                                  error=str(e)[:300])

    # ------------------------------------------------------------ snapshots
    def status(self):
        with self.lock:
            state = dict(self.state)
        if state.get("summary"):
            state["summary"] = {k: state["summary"][k]
                                for k in ("pages", "findings", "wall_s",
                                          "mode") if k in state["summary"]}
        return {"status": state, "ledger": self.ledger.verify(),
                "kinds": self.ledger.kinds(),
                "meters": self.meters.snapshot(),
                "license": license_mod.current_status(),
                "version": __version__,
                "relay_pool_size": len(self.relays)}

    def dashboard_data(self):
        data = self.status()
        data["findings"] = self.ledger.findings()[-25:]
        host_table = {}
        counters = data["meters"]["counters"]          # {name: {"lab1|lab2": n}}
        for cname, label_map in counters.items():
            if cname not in ("radar_requests_total", "radar_blocks_total",
                             "radar_net_errors_total", "radar_findings_total",
                             "radar_skips_total"):
                continue
            for lab, n in label_map.items():
                parts = lab.split("|")
                host = parts[0]
                a = parts[1] if len(parts) > 1 else ""
                row = host_table.setdefault(
                    host, {"ok": 0, "pressure": 0, "forbidden": 0,
                           "net": 0, "blocks": {}, "findings": 0,
                           "skips": {}})
                if cname == "radar_requests_total":
                    if a == "ok":
                        row["ok"] += n
                    elif a in ("pressure", "forbidden"):
                        row["pressure" if a == "pressure" else "forbidden"] += n
                elif cname == "radar_blocks_total":
                    row["blocks"][a] = row["blocks"].get(a, 0) + n
                elif cname == "radar_net_errors_total":
                    row["net"] += n
                elif cname == "radar_findings_total":
                    row["findings"] += n
                elif cname == "radar_skips_total":
                    row["skips"] = dict(row["skips"], **{a: n})
        data["host_table"] = host_table
        return data





class _Handler(BaseHTTPRequestHandler):
    server_version = "AkdiroRadar/" + __version__
    cs = None                                # injected by serve()

    def log_message(self, *args):
        pass

    # -------------------------------------------------------------- helpers
    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    # -------------------------------------------------------------- GET
    def do_GET(self):
        path = urlparse(self.path).path
        cs = self.cs
        if path == "/health":
            return self._json({"ok": True, "version": __version__})
        if path == "/":
            idx = os.path.join(REPO_ROOT, "dashboard", "index.html")
            if os.path.exists(idx):
                with open(idx, "rb") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8")
            return self._send(404, b"dashboard/index.html not deployed",
                              "text/plain")
        if path == "/api/status" or path == "/api/dashboard-data":
            return self._json(cs.dashboard_data() if path.endswith("dashboard-data")
                              else cs.status())
        if path == "/api/metrics":
            return self._send(200, cs.meters.prometheus(
                {"radar_ledger_rows": cs.ledger.count(),
                 "radar_relay_pool_size": len(cs.relays)}).encode("utf-8"),
                "text/plain; version=0.0.4")
        if path == "/api/report":
            md = runner.report_markdown(cs.ledger)
            return self._send(200, md.encode("utf-8"), "text/markdown")
        return self._send(404, b"not found", "text/plain")

    # -------------------------------------------------------------- POST
    def do_POST(self):
        cs = self.cs
        from urllib.parse import parse_qs
        qs = parse_qs(urlparse(self.path).query)
        token = (qs.get("token", [""])[0])
        if not secrets.compare_digest(token, cs.token):
            return self._json({"ok": False, "err": "bad token"}, 403)
        try:
            ln = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(min(ln, _MAX_BODY)) or b"{}")
        except ValueError:
            return self._json({"ok": False, "err": "bad json body"}, 400)
        manifest = body.get("manifest")
        if not manifest:
            md = body.get("manifest_dict")
            if not md:
                return self._json({"ok": False,
                                   "err": "manifest or manifest_dict required"}, 400)
            fd, manifest = tempfile.mkstemp(suffix=".json")
            with os.fdopen(fd, "w") as fh:
                json.dump(md, fh)
        res = cs.start_run(manifest,
                           max_pages=int(body.get("max_pages",
                                                  runner.MAX_PAGES_DEFAULT)),
                           workers=body.get("workers"),
                           deep_hosts=body.get("deep", []))
        return self._json(res, 202 if res["ok"] else 409)


def serve(port=9470, host="127.0.0.1", ledger_path="radar-ledger.db",
          relay_pool=None, meters=None):
    """Create, bind and serve forever; returns (httpd, control_server)."""
    cs = ControlServer(ledger_path, relay_pool, meters=meters)
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.daemon_threads = True
    _Handler.cs = cs
    return httpd, cs

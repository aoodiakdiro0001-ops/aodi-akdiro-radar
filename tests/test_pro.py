"""v1.1 test suite — meters/Prometheus, concurrency, server+dashboard,
license flow, SDK. All offline (localhost only).
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from urllib.parse import urlencode

from nexus import meters as meters_mod
from nexus import license as license_mod
from nexus import runner, sdk, server, storage, transport

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ------------------------------------------------------------------ stubs
class _Stub(BaseHTTPRequestHandler):
    hits = {}

    def do_GET(self):
        path = self.path.split("?")[0]
        _Stub.hits[path] = _Stub.hits.get(path, 0) + 1
        body = (b"<html><body><a href='/alpha'>a</a>"
                b"<a href='/admin/secret'>x</a></body></html>")
        if path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin/\n")
        elif path.startswith("/admin/"):
            self.send_error(403)
        else:
            self.send_response(200)
            self.send_header("Server", "stub/0.9.1")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):
        pass


def _start_stub():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, "http://127.0.0.1:%d" % httpd.server_port


def _manifest(*bases, deep=None):
    m = {"targets": [{"base_url": b + "/", "authorization":
                      {"declared": True, "contact": "audit@localhost"}}
                     for b in bases]}
    if deep:
        m["targets"][0]["authorization"]["deep"] = deep
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(m, fh)
    return path


def _get(url, expect_json=True, headers=None):
    req = Request(url, headers=headers or {})
    with urlopen(req, timeout=10) as r:
        data = r.read().decode("utf-8")
        return (json.loads(data) if expect_json else data), r.status


class MeterTests(unittest.TestCase):
    def test_increments_and_snapshot(self):
        m = meters_mod.Meters()
        m.note_response("h1", 200)
        m.note_response("h1", 429)
        m.note_forbidden("h1", 403)
        snap = m.snapshot()
        self.assertEqual(snap["counters"]["radar_requests_total"]["h1|ok"], 1)
        self.assertEqual(
            snap["counters"]["radar_requests_total"]["h1|pressure"], 1)
        self.assertEqual(snap["counters"]["radar_blocks_total"]["h1|403"], 1)

    def test_prometheus_format_scrapeable(self):
        m = meters_mod.Meters()
        m.note_response("target.example", 200)
        m.note_finding("target.example", "med")
        m.set_gauge("radar_ledger_rows", 7)
        text = m.prometheus()
        self.assertIn('radar_requests_total{host="target.example",cls="ok"} 1', text)
        self.assertIn('radar_findings_total{host="target.example",severity="med"} 1', text)
        self.assertIn("radar_ledger_rows 7", text)
        self.assertIn("radar_up_seconds", text)


class StorageThreadTests(unittest.TestCase):
    def test_concurrent_appends_stay_sealed(self):
        ledger = storage.Ledger(os.path.join(tempfile.mkdtemp(), "l.db"))
        def push(tag):
            for i in range(50):
                ledger.append("page", {"tag": tag, "i": i})
        threads = [threading.Thread(target=push, args=("t%d" % k,))
                   for k in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(ledger.count(), 200)
        self.assertTrue(ledger.verify()["ok"])


class ConcurrencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd1, cls.base1 = _start_stub()
        cls.httpd2, cls.base2 = _start_stub()
        _Stub.hits = {}
        cls.manifest = _manifest(cls.base1, cls.base2)

    @classmethod
    def tearDownClass(cls):
        cls.httpd1.shutdown()
        cls.httpd2.shutdown()

    def test_run_concurrent_polite_and_sealed(self):
        ledger = storage.Ledger(os.path.join(tempfile.mkdtemp(), "l.db"))
        orch = runner.Orchestrator(self.manifest, ledger)
        summary = orch.run_concurrent(workers=2, max_pages=2)
        # both hosts ran in parallel, neither stacked unpolitely
        self.assertGreaterEqual(summary["pages"], 4)
        hosts = {t["host"] for t in summary["targets"]}
        self.assertEqual(len(hosts), 2)
        # robots still enforced on every host
        self.assertEqual(_Stub.hits.get("/admin/secret", 0), 0)
        # seal chain intact across threads
        self.assertTrue(ledger.verify()["ok"])
        # meters recorded per-host traffic + ledger gauge
        snap = orch.meters.snapshot()
        self.assertIn("radar_requests_total", snap["counters"])
        self.assertEqual(snap["gauges"].get("radar_ledger_rows"),
                         ledger.count())

    def test_relay_pool_threadsafe_acquire(self):
        pool = transport.RelayPool(relays=["http://r-a", "http://r-b"])
        seen = set()
        def grab():
            for _ in range(30):
                r = pool.acquire()
                if r:
                    seen.add(r)
        ts = [threading.Thread(target=grab) for _ in range(6)]
        for th in ts:
            th.start()
        for th in ts:
            th.join()
        self.assertTrue(seen <= set(["http://r-a", "http://r-b"]))


class LicenseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ[license_mod.SECRET_ENV] = "test-secret-radar-0123"
        cls.home = tempfile.mkdtemp(prefix="lic-home-")

    @classmethod
    def tearDownClass(cls):
        os.environ.pop(license_mod.SECRET_ENV, None)

    def test_full_activate_flow(self):
        token = license_mod.make_license("team@example.test", tier="pro",
                                         days=30)
        fd, path = tempfile.mkstemp(suffix=".lic")
        with os.fdopen(fd, "w") as fh:
            json.dump(token, fh)
        res = license_mod.activate(path, home=self.home)
        self.assertTrue(res["ok"])
        self.assertEqual(res["buyer"], "team@example.test")
        st = license_mod.current_status(home=self.home)
        self.assertTrue(st["ok"])
        self.assertEqual(st["tier"], "pro")
        # tamper → rejected
        token["sig"] = "dead" * 16
        self.assertFalse(license_mod.verify_license(token)["ok"])

    def test_unlicensed_notice_in_report(self):
        ledger = storage.Ledger(os.path.join(tempfile.mkdtemp(), "l.db"))
        ledger.append("page", {"url": "http://x/"})
        self.assertIn("license:", runner.report_markdown(ledger))

    def test_forge_without_secret_fails(self):
        bogus = {"buyer": "bot@x", "tier": "lifetime", "issuer": "x",
                 "expiry": "9999-12-31", "issued": "2026-01-01",
                 "sig": "forged"}
        os.environ.pop(license_mod.SECRET_ENV, None)  # operator machine has it
        self.assertFalse(license_mod.verify_license(bogus)["ok"])
        os.environ[license_mod.SECRET_ENV] = "test-secret-radar-0123"


class SdkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd, cls.base = _start_stub()
        _Stub.hits = {}
        cls.manifest = _manifest(cls.base)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def test_three_line_embedding(self):
        result = sdk.orchestrate(self.manifest,
                                 os.path.join(tempfile.mkdtemp(), "l.db"),
                                 max_pages=2)
        self.assertGreaterEqual(result.summary["pages"], 1)
        self.assertTrue(result.seal["ok"])
        self.assertIn("radar_requests_total", result.meters.snapshot()["counters"])


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd, cls.base = _start_stub()
        _Stub.hits = {}
        cls.control_httpd, cls.cs = server.serve(
            port=0, ledger_path=os.path.join(tempfile.mkdtemp(), "l.db"))
        cls.url = "http://127.0.0.1:%d" % cls.control_httpd.server_address[1]
        threading.Thread(target=cls.control_httpd.serve_forever,
                         daemon=True).start()
        cls.manifest = _manifest(cls.base)

    @classmethod
    def tearDownClass(cls):
        cls.control_httpd.shutdown()
        cls.httpd.shutdown()

    def test_health_and_dashboard(self):
        data, code = _get(self.url + "/health")
        self.assertEqual(code, 200)
        self.assertTrue(data["ok"])
        html, code = _get(self.url + "/", expect_json=False)
        self.assertEqual(code, 200)
        self.assertIn("Akdiro", html)
        self.assertIn("لوحة الحياة", html)

    def test_post_run_requires_token(self):
        req = Request(self.url + "/api/run?" +
                      urlencode({"token": "wrong"}),
                      data=b"{}", method="POST",
                      headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=10) as r:
                code = r.status
        except HTTPError as e:
            code = e.code
        self.assertEqual(code, 403)

    def test_metric_and_report_endpoints(self):
        metrics, code = _get(self.url + "/api/metrics", expect_json=False)
        self.assertEqual(code, 200)
        self.assertIn("radar_", metrics)
        report, code = _get(self.url + "/api/report", expect_json=False)
        self.assertIn("seal chain", report)

    def test_full_api_run_flow(self):
        req = Request(self.url + "/api/run?" +
                      urlencode({"token": self.cs.token}),
                      data=json.dumps({"manifest": self.manifest,
                                       "max_pages": 2}).encode(),
                      method="POST", headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=10) as r:
            self.assertEqual(r.status, 202)
        deadline = time.time() + 20
        while time.time() < deadline:
            st, _ = _get(self.url + "/api/status")
            if not st["status"]["running"]:
                break
            time.sleep(0.3)
        self.assertFalse(st["status"]["running"])
        self.assertIsNone(st["status"].get("error"))
        self.assertGreaterEqual(st["status"]["summary"]["pages"], 1)
        dash, _ = _get(self.url + "/api/dashboard-data")
        self.assertTrue(any(v["ok"] > 0 for v in dash["host_table"].values()))
        self.assertEqual(_Stub.hits.get("/admin/secret", 0), 0)


class LicenseGenCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ[license_mod.SECRET_ENV] = "test-secret-radar-0123"

    def test_keygen_module(self):
        out = os.path.join(tempfile.mkdtemp(), "x.lic")
        proc = subprocess.run(
            [sys.executable, "-m", "tools.licensegen",
             "--buyer", "ops@example.test", "--tier", "pro", "--days", "7",
             "--out", out],
            capture_output=True, text=True, timeout=60, cwd=REPO)
        self.assertEqual(proc.returncode, 0, proc.stderr[-800:])
        with open(out) as fh:
            token = json.load(fh)
        res = license_mod.verify_license(token,
                                         secret=os.environ[license_mod.SECRET_ENV])
        self.assertTrue(res["ok"])
        self.assertEqual(res["tier"], "pro")


if __name__ == "__main__":
    unittest.main()

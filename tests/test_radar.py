"""Offline test suite — every compliance claim is pinned here.

Local stub HTTP server only; nothing touches the outside internet.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nexus import policy, profiler, runner, storage, throttle, transport

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _Stub(BaseHTTPRequestHandler):
    hits = {}
    last_ua = ""
    last_headers = {}

    def do_GET(self):
        path = self.path.split("?")[0]
        _Stub.hits[path] = _Stub.hits.get(path, 0) + 1
        _Stub.last_ua = self.headers.get("User-Agent", "")
        _Stub.last_headers = {k.lower(): v for k, v in self.headers.items()}
        body = (b"<html><head><title>ok</title></head><body>"
                b'<a href="/alpha">a</a><a href="/beta">b</a>'
                b'<a href="/admin/secret">x</a></body></html>')
        if path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin/\n")
        elif path.startswith("/admin/"):
            self.send_error(403)
        elif path == "/challenge":
            self.send_response(503, "Busy")
            self.send_header("Retry-After", "1")
            self.send_header("Server", "suspicious/1.2.3")
            self.send_header("cf-ray", "demo-ray-id")
            self.end_headers()
            self.wfile.write(b"<html>Just a moment... turnstile</html>")
        elif path == "/plain":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>plain page</body></html>")
        elif path in ("/", "/alpha", "/beta"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "suspicious/1.2.3")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def log_message(self, *args):
        pass


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _Stub.hits = {}
        _Stub.last_ua = ""
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()


class TransportTests(Base):
    def test_sends_our_ua_and_no_spoof_headers(self):
        resp = transport.fetch(self.base + "/plain")
        self.assertEqual(resp.status, 200)
        self.assertEqual(_Stub.last_ua, transport.UA)
        for banned in ("x-forwarded-for", "via"):
            self.assertNotIn(banned, _Stub.last_headers)
        self.assertNotIn("mozilla", _Stub.last_ua.lower())

    def test_non_2xx_are_data_not_errors(self):
        self.assertEqual(transport.fetch(self.base + "/admin/secret").status, 403)
        self.assertEqual(transport.fetch(self.base + "/nope").status, 404)

    def test_user_agent_cannot_be_overridden(self):
        with self.assertRaises(ValueError):
            transport.fetch(self.base + "/plain",
                            headers={"User-Agent": "EvilBot/9.9"})


class ThrottleTests(unittest.TestCase):
    def test_429_doubles_interval(self):
        b = throttle.TokenBucket(0.01, 2)
        base = b.snapshot()["interval_s"]
        b.on_response(429)
        self.assertAlmostEqual(b.snapshot()["interval_s"], base * 2, places=2)

    def test_retry_after_opens_cooldown(self):
        b = throttle.TokenBucket(0.01, 2)
        b.on_response(429, "5")
        self.assertTrue(b.snapshot()["cooling"])

    def test_success_decays(self):
        b = throttle.TokenBucket(0.01, 2)
        b.on_response(429)
        self.assertGreater(b.snapshot()["mult"], 1)
        b.on_response(200)
        self.assertLess(b.snapshot()["mult"], 2)

    def test_five_network_errors_open_breaker(self):
        b = throttle.TokenBucket(0.01, 2)
        for _ in range(5):
            b.on_network_error()
        self.assertTrue(b.snapshot()["cooling"])

    def test_forbidden_never_rotates_identity(self):
        b = throttle.TokenBucket(0.01, 2)
        b.on_forbidden()
        self.assertTrue(b.snapshot()["cooling"])  # cooldown, not laundering


class RelayPoolTests(unittest.TestCase):
    def test_rotation_only_on_network_errors(self):
        pool = transport.RelayPool(relays=["http://relay-a", "http://relay-b"])
        self.assertEqual(pool.acquire(), "http://relay-a")
        # a 403 on a bucket must NEVER touch the relay pool:
        bucket = throttle.TokenBucket(0.01, 2)
        bucket.on_forbidden()
        self.assertEqual(pool.acquire(), "http://relay-b")   # still healthy
        # only network truth rotates:
        pool.on_network_error(pool.acquire())
        nxt = pool.acquire()
        self.assertIn(nxt, pool.relays)

    def test_empty_pool_goes_direct(self):
        self.assertIsNone(transport.RelayPool().acquire())


class PolicyTests(Base):
    def test_robots_blocks_disallowed_path(self):
        robots = policy.Robots(self.base)
        self.assertTrue(robots.available)
        self.assertEqual(robots.allowed(self.base + "/admin/secret")[0], False)
        self.assertEqual(robots.allowed(self.base + "/")[0], True)

    def test_manifest_requires_authorization(self):
        with tempfile.TemporaryDirectory() as td:
            bad = os.path.join(td, "m.json")
            ok = os.path.join(td, "m2.json")
            with open(bad, "w") as fh:
                json.dump({"targets": [{"base_url": self.base}]}, fh)
            with open(ok, "w") as fh:
                json.dump({"targets": [{"base_url": self.base,
                                        "authorization": {
                                            "declared": True,
                                            "contact": "a@b"}}]}, fh)
            with self.assertRaises(policy.PolicyError):
                policy.load_manifest(bad)
            loaded = policy.load_manifest(ok)
            self.assertEqual(loaded[0]["host"].startswith("127.0.0.1"), True)

    def test_budget_monotonic_in_risk(self):
        ints = [policy.budget_for_risk(r)["min_interval_s"] for r in range(1, 6)]
        self.assertEqual(ints, sorted(ints))


class ProfilerTests(Base):
    def test_plain_target_low_risk(self):
        p = profiler.probe(self.base + "/plain")
        self.assertTrue(p["reachable"])
        self.assertLessEqual(p["risk"], 2)

    def test_challenge_target_high_risk(self):
        p = profiler.probe(self.base + "/challenge")
        self.assertGreaterEqual(p["risk"], 4)
        self.assertIn("interactive-challenge", p["reasons"])
        # and the honest consequence recorded in README: budget gets slower,
        # identity does not change (covered by TransportTests).

    def test_unreachable_is_risk_five(self):
        port = _free_port()
        p = profiler.probe("http://127.0.0.1:%d/" % port)
        self.assertFalse(p["reachable"])
        self.assertEqual(p["risk"], 5)


class RunnerTests(Base):
    def test_end_to_end_polite_run(self):
        ledger = storage.Ledger(os.path.join(tempfile.mkdtemp(), "l.db"))
        manifest = os.path.join(tempfile.mkdtemp(), "targets.json")
        with open(manifest, "w") as fh:
            json.dump({"targets": [{
                "base_url": self.base + "/",
                "authorization": {"declared": True, "contact": "audit@localhost"}}]}, fh)
        orch = runner.Orchestrator(manifest, ledger)
        summary = orch.run(max_pages=3)
        self.assertGreaterEqual(summary["pages"], 2)
        self.assertEqual(_Stub.hits.get("/admin/secret", 0), 0,
                         "robots must have prevented /admin/* fetches")
        self.assertTrue(ledger.verify()["ok"])
        kinds = ledger.kinds()
        for k in ("probe", "page", "finding", "summary"):
            self.assertIn(k, kinds)
        ids = [f["detail"] for f in ledger.findings()]
        # 6 missing headers + 1 versioned server, deduped across pages
        self.assertEqual(len(ids), 7)
        self.assertEqual(len(set(ids)), 7)

    def test_seal_chain_catches_tamper(self):
        ledger = storage.Ledger(os.path.join(tempfile.mkdtemp(), "l.db"))
        ledger.append("a", {"x": 1})
        ledger.append("b", {"y": 2})
        self.assertTrue(ledger.verify()["ok"])
        ledger.conn.execute("UPDATE ledger SET data='{\"forged\":1}' WHERE idx=1")
        res = ledger.verify()
        self.assertFalse(res["ok"])
        self.assertIn("broken_at_idx", res)

    def test_report_contains_audit_receipt(self):
        ledger = storage.Ledger(os.path.join(tempfile.mkdtemp(), "l.db"))
        ledger.append("page", {"url": self.base + "/", "status": 200})
        md = runner.report_markdown(ledger)
        self.assertIn("seal chain", md)
        self.assertIn("OK", md)


class CliDemoTests(unittest.TestCase):
    def test_demo_offline_green(self):
        outdir = tempfile.mkdtemp()
        proc = subprocess.run(
            [sys.executable, "-m", "nexus.cli", "demo", "--out", outdir],
            capture_output=True, text=True, timeout=120, cwd=REPO)
        self.assertEqual(proc.returncode, 0, proc.stderr[-1500:])
        with open(os.path.join(outdir, "summary.json")) as fh:
            data = json.load(fh)
        self.assertTrue(data["seal"]["ok"])
        self.assertGreaterEqual(data["summary"]["pages"], 2)
        self.assertEqual(data["summary"]["findings"], 7)


if __name__ == "__main__":
    unittest.main()

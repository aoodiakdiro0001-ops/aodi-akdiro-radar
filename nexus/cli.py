"""nexusctl — the face of Akdiro-Radar.

Commands: probe | init | run | report | verify | demo | version

Everything lives local: manifests, ledgers, reports. No cloud anywhere.
"""
import argparse
import json
import os
import sys
import tempfile
import threading

from . import __version__, license as license_mod, profiler, runner, server as server_mod, storage


def _print_help_meta(parser):
    parser.print_help()


def cmd_probe(args):
    out = profiler.probe(args.url, relay=None)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_init(args):
    sample = {
        "_note": "authorization.declared=true is SELF-ATTESTATION — edit honestly",
        "targets": [
            {
                "base_url": "http://127.0.0.1:8000",
                "notes": "example: your own local service",
                "authorization": {"declared": True, "contact": "you@example.test"},
            }
        ],
    }
    with open(args.path, "w") as fh:
        json.dump(sample, fh, ensure_ascii=False, indent=2)
    print("wrote %s — fill your targets honestly" % args.path)
    return 0


def cmd_run(args):
    ledger = storage.Ledger(args.ledger)
    orch = runner.Orchestrator(args.manifest, ledger,
                               deep_hosts=set(args.deep or []))
    summary = orch.run(max_pages=args.max_pages, depth1=not args.no_depth1,
                       log=lambda s: print(s, file=sys.stderr))
    print(json.dumps({"pages": summary["pages"], "findings": summary["findings"],
                      "wall_s": summary["wall_s"],
                      "seal": ledger.verify()},
                     ensure_ascii=False, indent=2))
    return 0


def cmd_report(args):
    ledger = storage.Ledger(args.ledger)
    md = runner.report_markdown(ledger)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(md)
        print("wrote %s" % args.out)
    else:
        print(md)
    return 0


def cmd_verify(args):
    ledger = storage.Ledger(args.ledger)
    res = ledger.verify()
    print(json.dumps(res, ensure_ascii=False))
    return 0 if res["ok"] else 1


# -------------------------------------------------------------- demo plumbing
_DEMO_ADMIN_HITS = [0]


def _demo_server():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            p = self.path.split("?")[0]
            body = (b"<html><head><title>demo</title></head><body>"
                    b'<a href="/alpha">alpha</a> <a href="/beta">beta</a> '
                    b'<a href="/admin/secret">admin</a>'
                    b"</body></html>")
            if p == "/robots.txt":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"User-agent: *\nDisallow: /admin/\n")
            elif p.startswith("/admin/"):
                _DEMO_ADMIN_HITS[0] += 1
                self.send_error(403)
            elif p == "/challenge":
                self.send_response(503, "gone fishing")
                self.send_header("Retry-After", "1")
                self.send_header("Server", "suspicious/1.2.3")
                self.end_headers()
                self.wfile.write(b"<html>Just a moment... turnstile</html>")
            else:
                self.send_response(200)
                self.send_header("Server", "suspicious/1.2.3")
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def cmd_demo(args):
    srv = _demo_server()
    base = "http://127.0.0.1:%d" % srv.server_port
    tmpdir = tempfile.mkdtemp(prefix="radar-demo-")
    manifest = os.path.join(tmpdir, "targets.json")
    ledger_path = os.path.join(tmpdir, "ledger.db")
    with open(manifest, "w") as fh:
        json.dump({"targets": [{"base_url": base + "/",
                                "notes": "local demo stub",
                                "authorization": {
                                    "declared": True,
                                    "contact": "demo@localhost"}}]}, fh)
    ledger = storage.Ledger(ledger_path)
    orch = runner.Orchestrator(manifest, ledger)
    summary = orch.run(max_pages=4)
    md = runner.report_markdown(ledger)
    out = os.path.join(args.out, "report.md")
    os.makedirs(args.out, exist_ok=True)
    with open(out, "w") as fh:
        fh.write(md)
    with open(os.path.join(args.out, "summary.json"), "w") as fh:
        json.dump({"manifest": manifest, "ledger": ledger_path,
                   "summary": {"pages": summary["pages"],
                               "findings": summary["findings"],
                               "wall_s": summary["wall_s"],
                               "targets": summary["targets"]},
                   "seal": ledger.verify()}, fh, ensure_ascii=False, indent=2)
    print(json.dumps({"base": base, "pages": summary["pages"],
                      "findings": summary["findings"],
                      "wall_s": summary["wall_s"],
                      "seal": ledger.verify(),
                      "admin_hits_expected_zero": _DEMO_ADMIN_HITS[0]},
                     ensure_ascii=False, indent=2))
    srv.shutdown()
    return 0


def cmd_serve(args):
    httpd, cs = server_mod.serve(port=args.port, host=args.host,
                                 ledger_path=args.ledger)
    printed = "127.0.0.1" if args.host in ("0.0.0.0", "") else args.host
    url = "http://%s:%d" % (printed, httpd.server_port or args.port)
    print("Akdiro-Radar control surface  →", url)
    print("dashboard                     →", url + "/")
    print("Prometheus                    →", url + "/api/metrics")
    print("POST /api/run token           →", cs.token)
    print("(all runs must come from a manifest with authorization.declared=true)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_activate(args):
    res = license_mod.activate(args.license)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("ok") else 1


def cmd_license(args):
    st = license_mod.current_status()
    print(json.dumps(st, ensure_ascii=False, indent=2))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="nexusctl",
                                 description="Akdiro-Radar orchestrator")
    ap.add_argument("--version", action="version",
                    version="Akdiro-Radar %s" % __version__)
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("probe", help="one honest probe of a target")
    p.add_argument("url")
    p.set_defaults(fn=cmd_probe)
    p = sub.add_parser("init", help="write a sample manifest")
    p.add_argument("--path", default="targets.local.json")
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("run", help="run the orchestrator over a manifest")
    p.add_argument("manifest")
    p.add_argument("--ledger", default="radar-ledger.db")
    p.add_argument("--max-pages", type=int, default=runner.MAX_PAGES_DEFAULT)
    p.add_argument("--no-depth1", dest="no_depth1", action="store_true")
    p.add_argument("--deep", nargs="*", default=[],
                   help="hosts you are explicitly authorized to scan at risk 5")
    p.set_defaults(fn=cmd_run)
    p = sub.add_parser("report", help="markdown audit receipt from a ledger")
    p.add_argument("ledger")
    p.add_argument("--out", default=None)
    p.set_defaults(fn=cmd_report)
    p = sub.add_parser("verify", help="verify the seal chain")
    p.add_argument("ledger")
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("demo", help="offline self-demo against a local stub")
    p.add_argument("--out", default="demo/out")
    p.set_defaults(fn=cmd_demo)
    p = sub.add_parser("serve", help="local control surface + dashboard + Prometheus")
    p.add_argument("--port", type=int, default=9470)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--ledger", default="radar-ledger.db")
    p.set_defaults(fn=cmd_serve)
    p = sub.add_parser("activate", help="install a signed license token")
    p.add_argument("license", help="path to the .lic file you received")
    p.set_defaults(fn=cmd_activate)
    p = sub.add_parser("license", help="print current license status")
    p.set_defaults(fn=cmd_license)
    args = ap.parse_args(argv)
    if not getattr(args, "fn", None):
        _print_help_meta(ap)
        return 2
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())

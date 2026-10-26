"""The orchestrator: manifest -> robots -> probe -> budget -> fetch -> inspect
-> sealed receipts. Cooling down replaces identity laundering, always.
"""
import json
import re
import time
from urllib.parse import urljoin, urlparse

from . import aggregate, policy, profiler, storage, throttle, transport

HREF_RE = re.compile(r"""href\s*=\s*["']([^"'#]+)["']""", re.I)
MAX_PAGES_DEFAULT = 8
DEPTH_EXTRACT_BYTES = 300000


class Orchestrator(object):
    def __init__(self, manifest_path, ledger, relay_pool=None, deep_hosts=frozenset()):
        self.targets = policy.load_manifest(manifest_path)
        self.ledger = ledger
        self.relays = relay_pool or transport.RelayPool()
        self.deep_hosts = set(deep_hosts)   # hosts whose risk-5 pages are allowed

    # ---------------------------------------------------------------- core
    def run(self, max_pages=MAX_PAGES_DEFAULT, depth1=True, log=None):
        started = time.time()
        summary = {"targets": [], "pages": 0, "findings": 0, "started": started}
        for t in self.targets:
            info = self._run_target(t, max_pages, depth1)
            summary["targets"].append(info)
            summary["pages"] += info["pulled"]
            summary["findings"] += info["findings"]
            if log:
                log("host=%s pulled=%d findings=%d states=%r"
                    % (t["host"], info["pulled"], info["findings"], info["states"]))
        summary["wall_s"] = round(time.time() - started, 2)
        self.ledger.append("summary", {"pages": summary["pages"],
                                       "findings": summary["findings"],
                                       "wall_s": summary["wall_s"]})
        return summary

    def _run_target(self, t, max_pages, depth1):
        info = {"host": t["host"], "contact": t["contact"], "robots": "",
                "risk": None, "pulled": 0, "findings": 0, "states": []}
        robots = policy.Robots(t["base_url"])
        info["robots"] = robots.status if robots.status else (
            "present" if robots.available else "absent")

        prof = profiler.probe(t["base_url"], relay=self.relays.acquire())
        self.ledger.append("probe", {"host": t["host"], "url": prof["url"],
                                     "reachable": prof["reachable"],
                                     "status": prof.get("status"),
                                     "risk": prof["risk"],
                                     "reasons": prof["reasons"]})
        info["risk"] = prof["risk"]
        if not prof["reachable"]:
            info["states"].append("unreachable")
            return info

        if robots.available:
            ok, why = robots.allowed(t["base_url"])
            if not ok:
                self.ledger.append("skip-robots", {"host": t["host"],
                                                   "url": t["base_url"]})
                info["states"].append("robots-disallowed")
                return info

        if prof["risk"] >= 5 and t["host"] not in self.deep_hosts:
            self.ledger.append("skip-risk5", {"host": t["host"],
                                              "reason": "authorized-only"})
            info["states"].append("risk5-authorized-only")
            return info

        bucket = throttle.TokenBucket(**policy.budget_for_risk(prof["risk"]))
        queue = [t["base_url"]]
        seen = set()
        dedupe = set()
        while queue and info["pulled"] < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            if robots.available:
                ok, why = robots.allowed(url)
                if not ok:
                    self.ledger.append("skip-robots", {"host": t["host"], "url": url})
                    info["states"].append("robots-skip:" + url)
                    continue
            try:
                bucket.acquire()
            except TimeoutError:
                info["states"].append("budget-timeout")
                break
            resp = self._fetch_with_resilience(url, bucket)
            if resp is None:
                info["states"].append("net-fail:" + url)
                continue
            self.ledger.append("page", {"host": t["host"], "url": resp.url,
                                        "status": resp.status,
                                        "ms": round(resp.elapsed_ms, 1),
                                        "risk": prof["risk"]})
            info["pulled"] += 1
            findings, sig = aggregate.inspect(resp.url, resp)
            for f in findings:
                key = (f["host"], f["kind"], f["detail"])
                if key not in dedupe:
                    dedupe.add(key)
                    self.ledger.append("finding", f)
                    info["findings"] += 1
            if depth1:
                text = resp.body[:DEPTH_EXTRACT_BYTES].decode("utf-8", "replace")
                for href in HREF_RE.findall(text):
                    nxt = urljoin(resp.url, href)
                    p = urlparse(nxt)
                    if p.scheme not in ("http", "https"):
                        continue
                    if p.netloc != t["host"]:
                        continue
                    if nxt not in seen and len(queue) < max_pages:
                        queue.append(nxt)
        return info

    # ------------------------------------------------------------ resilience
    def _fetch_with_resilience(self, url, bucket):
        """Network failures may move us to another relay (and cool the bucket).
        Forbidden/pressure responses may NEVER do so."""
        relay = self.relays.acquire()
        try:
            resp = transport.fetch(url, relay=relay)
        except transport.TransportError as e:
            self.relays.on_network_error(relay)
            bucket.on_network_error()
            self.ledger.append("net-error", {"url": url, "relay": relay or "direct",
                                             "err": str(e)[:120]})
            try:                       # one honest direct retry
                resp = transport.fetch(url, relay=None)
            except transport.TransportError as e2:
                bucket.on_network_error()
                return None
        hdr = {k.lower(): str(v) for k, v in resp.headers.items()}
        bucket.on_response(resp.status, hdr.get("retry-after"))
        if resp.status in (401, 403):
            bucket.on_forbidden()      # cool the host; identity stays
        return resp


def report_markdown(ledger):
    """Human-readable audit receipt from a sealed ledger."""
    v = ledger.verify()
    lines = ["# Akdiro-Radar — audit receipt", "",
             "- seal chain: **%s** (rows: %d)"
             % ("OK ✓" if v["ok"] else "TAMPERED at %s" % v.get("broken_at_idx"),
                v["rows"]),
             "- kinds: `%s`" % json.dumps(ledger.kinds(), sort_keys=True), "",
             "## findings", ""]
    for f in ledger.findings():
        lines.append("- **[%s]** `%s` %s — %s"
                     % (f["severity"], f["kind"], f["detail"], f["evidence"]))
    if not ledger.findings():
        lines.append("_no posture findings recorded_")
    return "\n".join(lines) + "\n"

"""Posture inspection: facts read off responses we were already allowed to get.

Scope discipline: we inspect the content/headers of pages the manifest
authorized us to pull. We do NOT brute-probe secret paths — the manifest
defines the scope, robots.txt shapes it.
"""
import hashlib
import re
from urllib.parse import urlparse

SEC_HEADERS = {
    "content-security-policy": ("CSP", "med"),
    "strict-transport-security": ("HSTS", "med"),
    "x-content-type-options": ("XCTO", "low"),
    "x-frame-options": ("XFO", "low"),
    "referrer-policy": ("RP", "low"),
    "permissions-policy": ("PP", "low"),
}

_VERSION_RE = re.compile(r"\d+\.\d+")


def host_of(url):
    return urlparse(url).netloc


def inspect(url, resp):
    """Return (findings, dedupe_sig)."""
    h = {k.lower(): str(v) for k, v in resp.headers.items()}
    findings = []
    for name, (short, sev) in SEC_HEADERS.items():
        if not h.get(name):
            findings.append({
                "host": host_of(url), "url": url, "kind": "missing-header",
                "detail": short, "severity": sev,
                "evidence": "response %d carried no %s header" % (resp.status, name),
            })
    server = h.get("server", "")
    if server and _VERSION_RE.search(server):
        findings.append({
            "host": host_of(url), "url": url,
            "kind": "versioned-server-header", "detail": server[:60],
            "severity": "low",
            "evidence": "Server header discloses a versioned fingerprint",
        })
    sig = "|".join(sorted(set("%s:%s" % (f["kind"], f["detail"]) for f in findings)))
    return findings, hashlib.sha256(sig.encode("utf-8")).hexdigest()[:16]

"""One-probe target profiling.

Risk is a *courtesy* score: 1 = fully open, 5 = interactive challenge /
auth wall. Its ONLY consequence is choosing a gentler budget (or refusing
to run at all for unauthorized deep targets). Markers we detect are facts
we report; nothing here changes how the client identifies itself.
"""
import time

from . import transport

_CHALLENGE_MARKERS = (
    "just a moment", "cf-chl", "cf_chl", "challenge-platform", "turnstile",
    "cf-mitigated", "checking your browser", "ddos protection", "px-captcha",
    "perimeterx", "datadome", "kasada", "_incapsula_resource", "radware", "sqreen",
)


def probe(url, timeout=25.0, relay=None):
    t0 = time.monotonic()
    try:
        resp = transport.fetch(url, timeout=timeout, relay=relay)
    except transport.TransportError as e:
        return {"url": url, "reachable": False, "error": str(e)[:160],
                "risk": 5, "reasons": ["unreachable"],
                "probed_in_ms": round((time.monotonic() - t0) * 1000.0, 1)}
    h = {k.lower(): str(v) for k, v in resp.headers.items()}
    body_l = resp.body[:60000].decode("utf-8", "replace").lower()
    server = h.get("server", "")
    cf = ("cf-ray" in h) or ("cloudflare" in server.lower())
    challenge = any(m in body_l for m in _CHALLENGE_MARKERS) or \
        ("challenge" in h.get("cf-mitigated", "").lower())
    reasons = []
    risk = 1
    if cf:
        risk += 1
        reasons.append("cloudflare-adjacent")
    if challenge:
        risk += 2
        reasons.append("interactive-challenge")
    if resp.status == 429:
        risk += 1
        reasons.append("rate-limited-on-probe")
    if resp.status in (401, 403):
        risk += 1
        reasons.append("403/401-on-probe")
        if ("login" in body_l or "sign in" in body_l):
            risk = 5
            reasons.append("auth-wall")
    return {"url": resp.url, "reachable": True, "status": resp.status,
            "server": server[:80], "cloudflare": cf, "challenge": challenge,
            "risk": int(min(risk, 5)), "reasons": reasons,
            "probed_in_ms": round((time.monotonic() - t0) * 1000.0, 1)}

"""Honest HTTP transport for Akdiro-Radar.

Non-negotiable design contracts (every test pins them):
  * a single, truthful User-Agent that identifies the tool + a contact
  * no TLS fingerprint crafting, no header stripping, no JA3/JA4 anything
  * ambient system proxies are refused (receipts must reflect the real path)
  * non-2xx responses are data, not errors — the pipeline wants status codes
"""
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

UA = ("Akdiro-Radar/1.0 "
      "(+https://github.com/aoodiakdiro0001-ops/aodi-akdiro-radar; "
      "mailto:baranavisat@gmail.com)")

BASE_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.7",
    "Accept-Language": "en",
}

_MAX_BODY = 2 * 1024 * 1024


class TransportError(Exception):
    """Network-level failure (DNS, refused, timeout) — retryable class."""


class Response(object):
    __slots__ = ("url", "status", "headers", "body", "elapsed_ms", "relay")

    def __init__(self, url, status, headers, body, elapsed_ms, relay=None):
        self.url = url
        self.status = status
        self.headers = headers          # dict, original case
        self.body = body                # bytes
        self.elapsed_ms = elapsed_ms
        self.relay = relay or ""


class RelayPool(object):
    """Ordered relays from env RADAR_RELAYS (comma-separated http:// URLs).

    A relay is marked dead for `backoff_s` after a NETWORK-level failure only.
    HTTP block / rate-limit decisions by a target must NEVER cause rotation —
    that is the bright line between resilience and defeat-evasion.
    """

    ENV = "RADAR_RELAYS"

    def __init__(self, backoff_s=60.0, relays=None):
        if relays is None:
            raw = os.environ.get(self.ENV, "")
            relays = [r.strip() for r in raw.split(",") if r.strip()]
        self.relays = list(relays)
        self.dead_until = [0.0] * len(self.relays)
        self.backoff_s = float(backoff_s)
        self._cursor = 0

    def acquire(self):
        """Return the first live relay URL, or None to go direct."""
        now = time.time()
        for k in range(len(self.relays)):
            idx = (self._cursor + k) % len(self.relays)
            if self.dead_until[idx] <= now:
                self._cursor = idx + 1
                return self.relays[idx]
        return None

    def on_network_error(self, relay):
        if relay in self.relays:
            self.dead_until[self.relays.index(relay)] = time.time() + self.backoff_s

    def __len__(self):
        return len(self.relays)


def fetch(url, method="GET", timeout=25.0, relay=None, headers=None, data=None):
    """Always returns a Response; raises TransportError on network failure."""
    h = dict(BASE_HEADERS)
    if headers:
        for k, v in headers.items():
            if k.lower() == "user-agent":
                raise ValueError("User-Agent is not overridable in this build")
            h[k] = v
    if relay:
        handler = urllib.request.ProxyHandler({"http": relay, "https": relay})
    else:
        handler = urllib.request.ProxyHandler({})   # refuse ambient proxies
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(_MAX_BODY)
            return Response(r.geturl(), r.status, dict(r.headers.items()), body,
                            (time.perf_counter() - t0) * 1000.0, relay)
    except urllib.error.HTTPError as e:
        body = e.read(_MAX_BODY)
        return Response(e.url, e.code, dict(e.headers.items()), body,
                        (time.perf_counter() - t0) * 1000.0, relay)
    except urllib.error.URLError as e:
        raise TransportError(str(getattr(e, "reason", e)))
    except (socket.timeout, OSError) as e:
        raise TransportError(str(e))


def status_class(status):
    if 200 <= status < 300:
        return "ok"
    if status == 429 or status == 503:
        return "pressure"
    if status in (401, 403):
        return "forbidden"
    if 400 <= status < 500:
        return "client-error"
    return "server-error"

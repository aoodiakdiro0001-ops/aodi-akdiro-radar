"""Adaptive politeness scheduler.

Backoff in this build means "become slower" — as a reaction to pressure
(429/503, network errors) — never "change who we are". When a target says
no (403), the host cools down; identity laundering is not implemented and
must not be. Those two sentences are the product's spine.
"""
import threading
import time


class TokenBucket(object):
    """Per-host budget: interval x burst, with adaptive pressure multiplier."""

    def __init__(self, min_interval_s, burst):
        self.min_interval = float(min_interval_s)
        self.burst = max(1, int(burst))
        self.tokens = float(self.burst)
        self.mult = 1.0                # adaptive multiplier 1.0 .. 32.0
        self.cool_until = 0.0          # circuit breaker (wall time)
        self.net_fails = 0
        self._lock = threading.Lock()
        self._last = time.monotonic()

    # -- internals ---------------------------------------------------------
    def _interval(self):
        return self.min_interval * self.mult

    # -- public ------------------------------------------------------------
    def acquire(self, timeout=120.0):
        """Block until one token is available or timeout (raises TimeoutError)."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                if now < self.cool_until:
                    wait = self.cool_until - now
                else:
                    self.tokens = min(
                        self.burst,
                        self.tokens + (now - self._last) / self._interval())
                    self._last = now
                    if self.tokens >= 1.0:
                        self.tokens -= 1.0
                        return True
                    wait = (1.0 - self.tokens) * self._interval()
            if time.monotonic() >= deadline:
                raise TimeoutError("rate budget timeout")
            time.sleep(min(max(wait, 0.0), 1.0))

    def on_response(self, status, retry_after=None):
        """Feed every real response back: pressure doubles the interval."""
        with self._lock:
            if status in (429, 503):
                self.mult = min(self.mult * 2.0, 32.0)
                if retry_after is not None:
                    try:
                        extra = min(float(retry_after), 300.0)
                        self.cool_until = max(self.cool_until,
                                              time.time() + extra)
                    except (TypeError, ValueError):
                        pass
            elif 200 <= status < 400:
                self.mult = max(1.0, self.mult * 0.9)

    def on_network_error(self):
        """Network truth (not a ban): slow down; hard-fail opens the breaker."""
        with self._lock:
            self.net_fails += 1
            self.mult = min(self.mult * 2.0, 32.0)
            if self.net_fails >= 5:
                self.cool_until = max(self.cool_until, time.time() + 300.0)
                self.net_fails = 0

    def on_forbidden(self, cool_s=300.0):
        """Target said no (401/403). We cool down. We do not rotate."""
        with self._lock:
            self.cool_until = max(self.cool_until, time.time() + float(cool_s))

    def snapshot(self):
        with self._lock:
            return {"mult": round(self.mult, 2), "cooling": time.time() < self.cool_until,
                    "burst": self.burst, "interval_s": round(self._interval(), 3)}

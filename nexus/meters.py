"""In-process meters + Prometheus text exposition. stdlib-only, thread-safe.

Zero scraping agents, zero phone-home: counters live in the process and are
exposed via `prometheus()` (scraped by Prometheus/Grafana through our own
HTTP server) and `snapshot()` (consumed by the dashboard). Honest limits:
single-process view — for fleet-wide metrics, scrape each shard.
"""
import threading
import time

# label NAMES per counter (values arrive as ordered tuples)
LABEL_NAMES = {
    "radar_probes_total": ("host", "risk"),
    "radar_requests_total": ("host", "cls"),
    "radar_blocks_total": ("host", "status"),
    "radar_net_errors_total": ("host", "relay"),
    "radar_relay_rotations_total": ("from",),
    "radar_findings_total": ("host", "severity"),
    "radar_skips_total": ("why", "host"),
}


def _status_class(status):
    if 200 <= status < 300:
        return "ok"
    if status in (429, 503):
        return "pressure"
    if status in (401, 403):
        return "forbidden"
    if 400 <= status < 500:
        return "client-error"
    if 500 <= status < 600:
        return "server-error"
    return "other"


def _esc(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


class Meters(object):
    """Counters + gauges behind one lock."""

    def __init__(self):
        self._lock = threading.Lock()
        self.started_at = time.time()
        self.counters = {}      # (name, labels_tuple) -> int
        self.gauges = {}        # name -> value

    # ------------------------------------------------------------ recording
    def inc(self, name, labels=(), n=1):
        with self._lock:
            key = (name, tuple(str(x) for x in labels))
            self.counters[key] = self.counters.get(key, 0) + n

    def set_gauge(self, name, value):
        with self._lock:
            self.gauges[name] = value

    def note_probe(self, host, risk):
        self.inc("radar_probes_total", (host, "risk%d" % int(min(max(risk, 1), 5))))

    def note_response(self, host, status):
        self.inc("radar_requests_total", (host, _status_class(status)))

    def note_forbidden(self, host, status):
        self.inc("radar_blocks_total", (host, str(status)))

    def note_net_error(self, host, relay):
        self.inc("radar_net_errors_total", (host, relay or "direct"))

    def note_relay_rotation(self, from_relay):
        self.inc("radar_relay_rotations_total", (from_relay or "direct",))

    def note_finding(self, host, severity):
        self.inc("radar_findings_total", (host, severity))

    def note_skip(self, why, host):
        self.inc("radar_skips_total", (why, host))

    # ------------------------------------------------------------ exporting
    def snapshot(self):
        """JSON-safe grouped view: {counter_name: {"lab1|lab2": count}}."""
        with self._lock:
            grouped = {}
            for (name, labels), val in self.counters.items():
                grouped.setdefault(name, {})["|".join(labels)] = val
            gauges = dict(self.gauges)
        return {"uptime_s": round(time.time() - self.started_at, 1),
                "counters": grouped, "gauges": gauges}

    def prometheus(self, extra_gauges=None):
        """Prometheus text format 0.0.4; safe for direct scraping."""
        lines = ["# Akdiro-Radar meters", ""]
        with self._lock:
            counters = {k: v for k, v in self.counters.items()}
            gauges = dict(self.gauges)
        if extra_gauges:
            gauges.update(extra_gauges)
        for (name, labels), val in sorted(counters.items()):
            names = LABEL_NAMES.get(name, ("a", "b", "c"))
            label_pair = ""
            if labels:
                label_pair = "{%s}" % ",".join(
                    '%s="%s"' % (names[i], _esc(x) if i < len(names) else _esc(x))
                    for i, x in enumerate(labels))
            lines.append("%s%s %d" % (name, label_pair, val))
        lines.append("# HELP radar_up_seconds process uptime")
        lines.append("# TYPE radar_up_seconds gauge")
        lines.append("radar_up_seconds %.1f" % (time.time() - self.started_at))
        for name, val in sorted(gauges.items()):
            lines.append("%s %s" % (name, val))
        return "\n".join(lines) + "\n"

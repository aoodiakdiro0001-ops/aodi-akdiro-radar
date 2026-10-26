"""Targets manifest, robots.txt handling and risk-based rate budgets.

A target may only run when its manifest entry carries
``authorization: {"declared": true, ...}``. Manifests are self-attestation;
the sealed receipts make that attestation auditable after the fact.

Budget table maps risk score -> (min_interval_s, burst). Higher risk means
slower and narrower — never smarter at getting around anything.
"""
import json
import urllib.parse
import urllib.robotparser

from . import transport

RISK_BUDGETS = {
    1: {"min_interval_s": 1.5, "burst": 4},
    2: {"min_interval_s": 3.0, "burst": 3},
    3: {"min_interval_s": 6.0, "burst": 2},
    4: {"min_interval_s": 12.0, "burst": 1},
    5: {"min_interval_s": 45.0, "burst": 1},
}


class PolicyError(Exception):
    """Raised when a manifest is unusable or an authorization is missing."""


def load_manifest(path):
    try:
        with open(path) as fh:
            data = json.load(fh)
    except OSError as e:
        raise PolicyError("cannot read manifest: %s" % e)
    except ValueError as e:
        raise PolicyError("manifest is not valid json: %s" % e)
    targets = []
    for i, t in enumerate(data.get("targets", [])):
        auth = t.get("authorization") or {}
        if auth.get("declared") is not True:
            raise PolicyError(
                "target #%d (%s) lacks authorization.declared=true — "
                "fill it honestly or do not scan it" % (i, t.get("base_url", "?")))
        parsed = urllib.parse.urlparse(t.get("base_url", ""))
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise PolicyError("target #%d has an unusable base_url" % i)
        targets.append({
            "base_url": t["base_url"],
            "host": parsed.netloc,
            "contact": auth.get("contact", ""),
            "notes": t.get("notes", ""),
        })
    return targets


def budget_for_risk(score):
    score = int(min(max(score, 1), 5))
    return dict(RISK_BUDGETS[score])


class Robots(object):
    """Fetch + comprehend robots.txt once per host; absent robots = allow."""

    def __init__(self, base_url, timeout=20.0):
        parsed = urllib.parse.urlparse(base_url)
        self.host = parsed.netloc
        self.agent = transport.UA.split("(")[0].strip()   # "Akdiro-Radar/1.0"
        self.available = False
        self.status = ""
        self._rp = None
        try:
            resp = transport.fetch(parsed._replace(
                path="/robots.txt", params="",
                query="", fragment="").geturl(), timeout=timeout)
        except transport.TransportError:
            self.status = "unreachable"
            return
        self.status = str(resp.status)
        if resp.status != 200:
            return
        try:
            text = resp.body.decode("utf-8", "replace")
        except Exception:
            return
        if "user-agent" not in text.lower():
            self.status = "not-robots"           # e.g. an SPA error page
            return
        rp = urllib.robotparser.RobotFileParser()
        rp.parse(text.splitlines())
        self._rp = rp
        self.available = True

    def allowed(self, url):
        if self._rp is None:
            return True, "robots-" + self.status
        try:
            ok = self._rp.can_fetch(self.agent, url)
        except Exception:
            ok = True
        return ok, ("robots-allow" if ok else "robots-disallow")

"""Honest license machinery for the paid release.

Format: a JSON token {"buyer","tier","expiry","issued","sig"} where
sig = HMAC-SHA256(secret, canonical_json_without_sig). The secret lives in
the operator's environment (RADAR_LICENSE_SECRET) — never in the repo.

Honest position (restated in SECURITY.md): the codebase is MIT open-source,
so this checker is a *sales agreement enforcer*, not a cryptography fence —
stripping it breaches the paid license, not physics. It binds buyer email
+ expiry; unlicensed mode stays fully functional but every report says
"UNLICENSED" explicitly.
"""
import datetime
import hashlib
import hmac
import json
import os

SECRET_ENV = "RADAR_LICENSE_SECRET"

REQUIRED_FIELDS = ("buyer", "tier", "expiry", "issued")


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sig(secret, payload):
    return hmac.new(secret.encode("utf-8"),
                    _canonical(payload).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def make_license(buyer, tier="lifetime", days=0, secret=None, issued=None):
    """Operator-side keygen used by tools/licensegen.py."""
    secret = secret or os.environ.get(SECRET_ENV, "")
    if not secret:
        raise ValueError("RADAR_LICENSE_SECRET not set")
    issued = issued or datetime.date.today().isoformat()
    if tier == "lifetime":
        expiry = "9999-12-31"
    else:
        expiry = (datetime.date.today() + datetime.timedelta(days=max(int(days), 0))
                  ).isoformat()
    payload = {"buyer": buyer, "tier": tier, "expiry": expiry, "issued": issued}
    token = dict(payload)
    token["sig"] = _sig(secret, payload)
    return token


def verify_license(token, secret=None, today=None):
    if not isinstance(token, dict) or any(f not in token for f in REQUIRED_FIELDS):
        return {"ok": False, "err": "malformed license"}
    payload = {k: token[k] for k in REQUIRED_FIELDS}
    secret = secret if secret is not None else os.environ.get(SECRET_ENV, "")
    if not secret or not hmac.compare_digest(str(token.get("sig", "")),
                                             _sig(secret, payload)):
        return {"ok": False, "err": "bad signature"}
    today = today or datetime.date.today().isoformat()
    if token["expiry"] < today:
        return {"ok": False, "err": "expired %s" % token["expiry"]}
    return {"ok": True, "buyer": token["buyer"], "tier": token["tier"],
            "expiry": token["expiry"]}


def store_path(home=None):
    home = home or os.path.expanduser("~")
    return os.path.join(home, ".akdiro-radar", "license.json")


def activate(token_path, home=None):
    with open(token_path) as fh:
        token = json.load(fh)
    res = verify_license(token)
    if not res["ok"]:
        return res
    sp = store_path(home)
    os.makedirs(os.path.dirname(sp), exist_ok=True)
    os.chmod(os.path.dirname(sp), 0o700)
    with open(sp, "w") as fh:
        json.dump(token, fh)
    os.chmod(sp, 0o600)
    return {"ok": True, "buyer": token["buyer"], "tier": token["tier"],
            "expiry": token["expiry"], "stored_at": sp}


def current_status(home=None):
    sp = store_path(home)
    if not os.path.exists(sp):
        return {"ok": False, "err": "unlicensed", "notice": "UNLICENSED COPY"}
    try:
        with open(sp) as fh:
            token = json.load(fh)
    except (OSError, ValueError):
        return {"ok": False, "err": "unreadable license store",
                "notice": "UNLICENSED COPY"}
    res = verify_license(token)
    res.setdefault("notice", "")
    return res

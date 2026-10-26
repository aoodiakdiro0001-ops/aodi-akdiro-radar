#!/usr/bin/env python3
"""Operator keygen — NEVER runs in CI, secret never committed.

Usage:
    RADAR_LICENSE_SECRET='long-random' python3 -m tools.licensegen \
        --buyer team@example.com --tier lifetime --out baran.lic

Tiers: lifetime | pro-N-days (tier "pro" + --days N)
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nexus import license as lic  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(prog="licensegen")
    ap.add_argument("--buyer", required=True, help="buyer email / company")
    ap.add_argument("--tier", default="lifetime", choices=["lifetime", "pro"])
    ap.add_argument("--days", type=int, default=0, help="for tier=pro")
    ap.add_argument("--out", required=True, help="write token to this path")
    args = ap.parse_args(argv)
    token = lic.make_license(args.buyer, tier=args.tier, days=args.days)
    with open(args.out, "w") as fh:
        json.dump(token, fh, indent=2)
    os.chmod(args.out, 0o600)
    print("wrote %s — buyer=%s tier=%s expiry=%s"
          % (args.out, token["buyer"], token["tier"], token["expiry"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())

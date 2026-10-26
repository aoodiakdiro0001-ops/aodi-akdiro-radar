# SECURITY.md — Aodı-Akdiro Radar

**Owner / security contact:** Baran Avisat · baranavisat@gmail.com ·
WhatsApp +90 531 326 37 22

## The bright line (also tested in `tests/test_radar.py`)

1. **No evasion machinery.** No TLS/JA3/JA4 spoofing, no header laundering,
   no browser-emulation fingerprints. `transport.fetch` serves one truthful
   User-Agent; tests assert overrides are refused and that no
   `X-Forwarded-For`/`Via` laundering happens.
2. **Blocks are respected, not fought.** A 401/403 opens a cooldown on that
   host. Relay rotation triggers on network-level failures only; tests pin
   that forbidden responses leave the relay pool untouched.
3. **Authorization is required, self-attested, auditable.** `policy`
   refuses manifests without `authorization.declared=true`; every run seals
   `probe/page/skip/finding/summary` rows into an append-only sha256 chain so
   the attestation can be demonstrated later.
4. **Scope comes from the manifest + robots.txt.** No hidden-path brute
   probing in this build; link traversal is depth-1 and same-host only.

## Threat model of the build itself

- **Local-first:** ledger, manifests, reports live in your machine's files.
  Nothing is uploaded anywhere by this tool (the only outbound traffic is to
  the targets you declared, plus optional relays you configured).
- **Relay credentials:** read from `RADAR_RELAYS` at runtime. Never stored,
  never logged, never committed — `.gitignore` blocks secrets.
- **Ledger integrity:** seal chain detects rewrite/tamper and pinpoints the
  forged index. It is not a cryptographic notarisation; it prevents silent
  history editing and makes accidents obvious.
- **No telemetry,** no update pings, no phone-home.

## What this tool cannot protect you from

Using it against systems you are not authorized to test. Your manifest is
self-attested; the waves of receipts are on you. Scan people/s you have
permission for — politeness is enforced by code, permission is enforced by you.

## Licensing enforcement — honest terms (v1.1)

The `license.py` machinery (HMAC-SHA256 tokens, secret in the operator
environment, never committed) enforces the *sale*, not secrecy of physics:
the GitHub tree is MIT, so a determined user can stub the checker locally —
that is a breach of the paid license terms, not a cryptographic guarantee.
Unlicensed mode remains fully functional and receipts label it
`UNLICENSED COPY`; activated tokens bind buyer email + expiry and are the
basis for support entitlements.

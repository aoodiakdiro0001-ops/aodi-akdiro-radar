# Aodı-Akdiro Radar — target-aware polite scraping & posture orchestrator

**Orchestrator-first**: one probing request classifies a target's defenses,
risk decides how gentle the pipeline is, relays only move on network truth,
and **every request leaves a sealed receipt**. stdlib-only, zero dependencies,
MIT © 2026 Baran Avisat.

> This build is explicitly **not** an anti-bot-bypass toolkit. Three things it
> does not and will not do (pinned by tests, stated in SECURITY.md):
> 1. no TLS/JA3/HTTP2 fingerprint spoofing — one truthful User-Agent;
> 2. no identity rotation to defeat 403/429 decisions — the host cools down;
> 3. no "99.9% success" promises — proven politeness metrics instead.

If a target ought not to be scanned, this tool is the wrong tool. If you own
it, are licensed to test it, or its `robots.txt` welcome supports polite
monitoring — this is a disciplined, auditable way to do it.

## Architecture

```
target manifest (self-attested authorization)
        │
[ 1. Profiler   ] one honest probe → risk 1..5 + reasons (facts, reported)
        │
[ 2. Policy     ] robots.txt comprehension + risk→budget (slower, not smarter)
        │
[ 3. Throttle   ] token bucket · full-jitter-free intervals · breaker on abuse
        │        429/503 → interval doubles (max ×32) · Retry-After honored
        │        401/403    → host cools down (identity NEVER rotates)
        │        net-error  → relay rotation allowed (network truth only)
        │
[ 4. Aggregate  ] security-posture facts from pages we were allowed to fetch
        │
[ 5. Ledger     ] sha256 seal chain — probe/page/skip/finding/summary rows
```

Risk table (interval seconds × burst): 1→(1.5,4) · 2→(3,3) · 3→(6,2) ·
4→(12,1) · 5→(45,1). Risk 5 targets are **authorized-only**: skipped unless
the host is passed to `--deep`.

## What the seal chain proves

Every probe, page pull, robots-skip, net-error and posture finding is an
append-only row; each row's hash binds the previous one; rewriting history
breaks exactly the forged index:

```json
{"ok": true, "rows": 13}
```
tampered ledger → `{"ok": false, "broken_at_idx": 1}`

## Quickstart

```bash
python3 -m unittest discover tests   # 34 offline tests, green
python3 -m nexus.cli demo            # local stub server, zero internet
python3 -m nexus.cli init --path targets.local.json
python3 -m nexus.cli probe http://your-target/
python3 -m nexus.cli run targets.local.json --ledger radar-ledger.db
python3 -m nexus.cli report radar-ledger.db --out REPORT.md
python3 -m nexus.cli verify radar-ledger.db
```

### Embed in your app — 3 lines

```python
from nexus.sdk import orchestrate
result = orchestrate("targets.local.json", "radar-ledger.db", workers=4)
print(result.summary["pages"], "sealed:", result.seal)
```

### Or run the control surface + dashboard + Prometheus

```bash
python3 -m nexus.cli serve --port 9470     # POST-run token prints once
```

Open http://127.0.0.1:9470/ — Arabic RTL panel with live meters, per-host
table, findings feed and a token-guarded run button. `/api/metrics` is
Prometheus text format (scrape it directly); `/api/report` serves the
markdown receipt. Full endpoint table + Python/Go/curl 3-liners: **docs/API.md**.


### Manifest (honesty is load-bearing)

```json
{
  "targets": [
    {
      "base_url": "http://127.0.0.1:8000",
      "notes": "our own service",
      "authorization": {"declared": true, "contact": "team@example.test"}
    }
  ]
}
```

`authorization.declared: true` is **self-attestation** — the manifest refuses
targets without it, and the sealed receipts make the attestation auditable.
Unauthorized use of anything you scan remains your legal responsibility.

### Relays (resilience, not evasion)

```bash
export RADAR_RELAYS="http://user:pass@anyip-host:port,http://user:pass@backup:port"
```

A relay is rotated **only** after a network-level failure (DNS/timeout/refused)
— never as a reaction to being blocked. Tests pin this distinction.

![Akdiro-Radar live dashboard](assets/dashboard.png)

## Concurrency (B2B reality, honestly)

`run_concurrent(workers=N)` parallelizes **across hosts** on a thread pool
while each host keeps its own bucket — politeness per host is never stacked
against itself; the seal chain stays intact under threads (RLock-guarded,
test-pinned). Honest limit: meters are in-process view; run one shard per
bunch of targets and scrape each `/api/metrics`.

## Licensing (paid build, stated plainly)

`Gumroad` buyers receive an HMAC-SHA256 license token bound to buyer email:

```bash
nexusctl activate baran.lic && nexusctl license
```

Verification is offline; no phone-home, ever. The repo itself is MIT
open-source, so the checker is a sales-agreement enforcer, not a crypto
fence — unlicensed copies stay fully functional and every generated report
labels itself **UNLICENSED COPY** until activated. We would rather sell
receipts than lie about lock strength.

## What it finds today
Security-posture facts from pages in scope: missing `CSP`/`HSTS`/
`X-Content-Type-Options`/`X-Frame-Options`/`Referrer-Policy`/
`Permissions-Policy`, versioned `Server` headers. That is honest headcount,
not an exploitation framework.

## Honest limits

- no JA3/JA4, no HTTP/2 client forging, no CAPTCHA solvers — by design
- no form-filling cep JS execution beyond plain HTML hrefs (depth-1 links)
- findings are posture signals, not confirmed vulnerabilities
- relay rotation is failure-resilience only; this tool does not fight bans
- SQLite ledger is local; back it up like any database

## Support / contact

- Email: **baranavisat@gmail.com**
- WhatsApp: **+90 531 326 37 22** ([wa.me/905313263722](https://wa.me/905313263722))
- GitHub: [aoodiakdiro0001-ops](https://github.com/aoodiakdiro0001-ops)
- BTC: `bc1q8dhtdrndxsl70e97t8grydfe6pjue37zrhzf6c`
- USDT (TRC20): `TLWdTjqqogkXNEXGiPWsGdjFP6ioycxeWW`

MIT License © 2026 Baran Avisat — Aodı Akdıro Suite

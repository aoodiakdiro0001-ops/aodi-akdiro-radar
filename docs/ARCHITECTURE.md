# ARCHITECTURE.md — Aodı-Akdiro Radar

One orchestrator, five cooperating layers, one ledger. stdlib-only.

```
                    ┌───────────────────────────────────────────┐
manifest (JSON with per-target authorization.declared)
                    └───────────────────────────────────────────┘
                                   │
        ┌──────────────────────────▼──────────────────────────┐
        │ profiler.probe() — ONE request per target            │
        │   returns risk 1..5 + reasons (facts, not guesses)   │
        └──────────────────────────┬──────────────────────────┘
                                   │ risk
        ┌──────────────────────────▼──────────────────────────┐
        │ policy.budget_for_risk() → (min_interval, burst)     │
        │ policy.Robots() → cached robots.txt comprehension    │
        └──────────────────────────┬──────────────────────────┘
                                   │
        ┌──────────────────────────▼──────────────────────────┐
        │ throttle.TokenBucket — per host, thread-safe          │
        │   on_response(429/503) → interval ×2 (cap ×32)        │
        │   on_retry_after → cooldown window honored            │
        │   on_forbidden   → cooldown only (never rotation)     │
        │   on_net_error   → ×2 slow + breaker after 5 fails    │
        └──────────────────────────┬──────────────────────────┘
                                   │
        ┌──────────────────────────▼──────────────────────────┐
        │ transport.fetch — honest UA, no ambient proxies,      │
        │ optional relay (pool rotates on network truth only)   │
        └──────────────────────────┬──────────────────────────┘
                                   │
        ┌──────────────────────────▼──────────────────────────┐
        │ aggregate.inspect — posture facts from fetched pages  │
        │   missing security headers · versioned Server header  │
        └──────────────────────────┬──────────────────────────┘
                                   │
        ┌──────────────────────────▼──────────────────────────┐
        │ storage.Ledger — append-only sha256 seal chain        │
        │ kinds: probe · page · skip-robots · skip-risk5 ·      │
        │        net-error · finding · summary                  │
        └──────────────────────────────────────────────────────┘
```

## Receipt lifecycle

1. `probe` — the single probing request and its risk classification.
2. `page` — every page actually pulled: URL, status, latency, target risk.
3. `skip-*` — every polite refusal (robots, risk-5 unauthorized).
4. `finding` — deduped posture observation.
5. `summary` — run totals; the chain verifiable by `nexusctl verify`.

## Invariants

- relay rotation ⟺ network error. Blocked ≠ unreachable; tests enforce it.
- risk only ever makes the pipeline slower or stops it. It never disguises it.
- UA override is refused by `transport.fetch` (ValueError), not by convention.

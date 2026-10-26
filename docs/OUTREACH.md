# OUTREACH.md — B2B playbook for Akdiro-Radar

The product wins deals with **receipts and CI**, not marketing. Copy-paste
these as-is and attach the artifacts listed.

## Template A — proxy vendors (free credits / partnership)

> **Subject: Akdiro-Radar — a paid orchestrator that asks YOUR gateways to
> proxy politely (free credits partnership?)**
>
> Hi team — we shipped Aodı-Akdiro Radar v1.1.0: a target-aware scraping
> orchestrator whose relay pool rotates **only on network-level failures**
> (DNS/timeout/refused). When a target says 403/429, the host cools down —
> we never burn your residential inventory against bans. Every request is
> sealed into a sha256 receipt chain, and live Prometheus metrics expose
> your relay health per attempt.
>
> Since our relay usage is compliance-first (robots.txt honored, buckets
> per-host, auditable receipts), it is a low-risk ad for your network:
> metered, polite, documented. Would you consider hosting credits for a
> partnership listing in our docs? Our CI: green on Python 3.9–3.12
> (github.com/aoodiakdiro0001-ops/aodi-akdiro-radar).
>
> baranavisat@gmail.com · WhatsApp +90 531 326 37 22

Attach: dashboard screenshot (assets/dashboard.png), release link.

## Template B — SOC2 / compliance buyers

> **Subject: sealed audit receipts for your scraping — 3 lines to embed**
>
> Same pitch: orchestrate(manifest, ledger) → every probe/page/finding
> sealed (sha256 chain, tamper → broken_at_idx), `nexusctl verify` proves it
> later, Prometheus meters for your Grafana, license tokens bound to buyer
> email. Perfect for teams that must PROVE scraping policy — not just claim it.

## Attachments checklist per deal

1. `github.com/aoodiakdiro0001-ops/aodi-akdiro-radar/actions` — green CI build
2. Release v1.1.0 with demo receipts + dashboard shot
3. The receipts ledger from `python3 -m nexus.cli demo` (13 sealed rows)
4. SECURITY.md — the three no-go lines, tested and pinned

## Honest niches to attack first

- Consultancies that need **documented** recon-before-report (your receipts
  are their deliverable).
- Uptime/posture monitor fans — missing security headers is an easy
  board-friendly report.
- Regulated shops (health, fintech, gov vendors) where "polite + licensed +
  sealed" beats every bash script they tried.

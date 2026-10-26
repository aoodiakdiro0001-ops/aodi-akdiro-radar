"""Aodı-Akdiro Radar — target-aware, polite scraping & posture orchestrator.

Compliance-first by design:
  * one truthful User-Agent, no TLS/JA3/HTTP2 fingerprint work
  * relays rotate ONLY on network failures — never to defeat a block
  * 403/429 NEVER trigger identity rotation; the host cools down instead
  * targets require a self-attested authorization declaration in the manifest
  * every request/probe/finding lands in a sealed sha256 ledger

MIT (c) 2026 Baran Avisat
"""

__version__ = "1.0.0"

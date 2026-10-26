# SETUP.md

## Requirements

- Python 3.8+ (CI runs 3.9–3.12 on ubuntu-24.04)
- zero dependencies — stdlib only

## Clone & check

```bash
git clone https://github.com/aoodiakdiro0001-ops/aodi-akdiro-radar.git
cd aodi-akdiro-radar
python3 -m unittest discover tests        # expect: OK (20 tests)
python3 -m nexus.cli demo                # local stub demo, offline
```

## Configure targets

```bash
python3 -m nexus.cli init --path targets.local.json
# edit targets.local.json: base_url + authorization.declared/contact — honestly
```

## Optional relays (resilience for network failures only)

```bash
export RADAR_RELAYS="http://user:pass@relay-host:port"   # comma-separate for more
```

Run, then read your receipts:

```bash
python3 -m nexus.cli run targets.local.json --ledger radar-ledger.db
python3 -m nexus.cli report radar-ledger.db --out REPORT.md
python3 -m nexus.cli verify radar-ledger.db
```

## Scheduling

`nexusctl run` is one polite pass. For recurring monitoring, schedule the same
command with cron/launchd/supervisord — the ledger is append-only across runs
and `verify` stays green across restarts.

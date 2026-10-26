"""3-line SDK facade — embed Akdiro-Radar inside your own application.

```python
from nexus.sdk import orchestrate
result = orchestrate("targets.local.json", "radar-ledger.db")
print(result.summary, result.seal)
```


Thread-safe by construction; politeness semantics identical to the CLI.
"""
from collections import namedtuple

from . import license as _license
from . import runner, storage

RunResult = namedtuple("RunResult", "summary ledger meters seal")


def orchestrate(manifest, ledger_path="radar-ledger.db", max_pages=8,
                workers=None, deep_hosts=(), relay_pool=None, log=None):
    """Run a manifest politely; returns RunResult(summary, ledger, meters, seal)."""
    ledger = storage.Ledger(ledger_path)
    orch = runner.Orchestrator(manifest, ledger, relay_pool=relay_pool,
                               deep_hosts=deep_hosts)
    if workers:
        summary = orch.run_concurrent(workers=workers, max_pages=max_pages,
                                      log=log)
    else:
        summary = orch.run(max_pages=max_pages, log=log)
    return RunResult(summary, ledger, orch.meters, ledger.verify())

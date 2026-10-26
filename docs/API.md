# API.md — Akdiro-Radar

## Library (Python, 3 lines)

```python
from nexus.sdk import orchestrate
result = orchestrate("targets.local.json", "radar-ledger.db", workers=4)
print(result.summary["pages"], result.seal, result.meters.snapshot())
```

`RunResult` fields: `summary` (pages/findings/wall_s/mode/targets[]) ·
`ledger` (verify/kinds/findings/rows) · `meters` (snapshot/prometheus) ·
`seal` ({ok, rows}).

## HTTP control surface (zero-dep, localhost)

```bash
python3 -m nexus.cli serve --port 9470
# prints the POST run-token once; dashboard at http://127.0.0.1:9470/
```

| Endpoint | Method | Auth | Returns |
|---|---|---|---|
| `/` | GET | — | Arabic RTL dashboard |
| `/health` | GET | — | `{"ok": true, "version": …}` |
| `/api/status` | GET | — | run state + meters + license + seal |
| `/api/dashboard-data` | GET | — | combined JSON (status + host table + findings) |
| `/api/metrics` | GET | — | **Prometheus text 0.0.4** (direct scrape) |
| `/api/report` | GET | — | markdown audit receipt |
| `/api/run?token=…` | POST | token | start run: `{"manifest": path}` or `{"manifest_dict": {...}}`, optional `max_pages`, `workers`, `deep` |

POST without the token → 403. The server binds `127.0.0.1` unless you pass
`--host`. The token prints at bootstrap; it is per-process.

### Run it from anywhere (3-liners)

**curl**
```bash
curl -X POST "http://127.0.0.1:9470/api/run?token=$TOKEN" \
     -d '{"manifest": "targets.local.json", "workers": 4}'
```

**Go (net/http, honest subprocess-free client)**
```go
body := strings.NewReader(`{"manifest":"targets.local.json","workers":4}`)
req, _ := http.NewRequest("POST", "http://127.0.0.1:9470/api/run?token="+token, body)
req.Header.Set("Content-Type", "application/json")
http.DefaultClient.Do(req)
```

**Python (urllib, stdlib only)**
```python
from urllib.request import Request, urlopen
req = Request("http://127.0.0.1:9470/api/run?token=" + TOKEN,
              data=b'{"manifest": "targets.local.json"}', method="POST")
print(urlopen(req).status)          # 202 started
```

## Prometheus metrics

`/api/metrics` emits `radar_requests_total{host,cls}` (ok/pressure/forbidden/
client-error/server-error), `radar_blocks_total{host,status}`,
`radar_net_errors_total{host,relay}`, `radar_relay_rotations_total{from}`,
`radar_findings_total{host,severity}`, `radar_skips_total{why,host}`,
`radar_probes_total{host,risk}`, `radar_ledger_rows`, `radar_relay_pool_size`,
`radar_up_seconds`. Point a Prometheus scrape job at
`http://your-shard:9470/api/metrics` — single-process meter per shard is the
honest scope.

## License tokens (paid build)

```bash
nexusctl activate baran.lic     # HMAC-SHA256 token bought on Gumroad
nexusctl license                # current status; reports stamp it honestly
```

Verification is offline (no phone-home). Unlicensed copies stay functional
and every report/receipt labels itself `UNLICENSED COPY` on purpose.

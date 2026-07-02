# DAST Pipeline

## Scan flow

```
Auth → Katana → httpx → ZAP → Wapiti → Nuclei → noise.Apply → Report
```

## Noise control

- **Scope deny** (YAML `scope.deny` + ZAP `excludePaths`): blocks `%PUBLIC_URL%`, double-encoded `%25`, `/manifest.json`, `/static/*`, and binary assets.
- **`noise.IsGarbageDiscoveryURL`**: shared filter for Katana feed, ZAP requestor, and httpx input.
- **Rule 10027 suppression**: CRA `%PUBLIC_URL%` HTML comments excluded by default in `noiseControl.suppression.exclude`.
- **Passive dedupe**: ZAP numeric plugin IDs dedupe by `ruleId + host` (not full URL).

## ZAP

- Re-enabled with `zapAjaxMaxCrawlStates: 200`, passive wait 120s.
- Spider seeds: configured `baseUrl` + `startPoints` only (not full Katana feed — OOM protection).
- **Katana → ZAP requestor**: up to 500 filtered GET probes (`DAST_ZAP_FEED_PROBE_MAX`), prioritizing `/api/` and page-like URLs.
- Override skip: `DAST_SKIP_ZAP=1` or worker `-skip-zap`.

## httpx

- Step `httpxProbe` after Katana, before ZAP.
- Input: cleaned feed (cap 3000, `DAST_HTTPX_INPUT_MAX`).
- Output: INFO findings `httpx:probe`, artifact `httpx-results.jsonl`.
- Optional: `DAST_HTTPX_DROP_4XX=1` removes 404/410 URLs from discovery feed.
- Binary: `DAST_HTTPX_BIN` (default `httpx`).

## Wapiti

- Runs sequentially for every URL in `nucleiBasesFromTargets` (base + all `startPoints`).
- Findings merged with dedupe by `locationKey`.

## API pagination

| Endpoint | Params | Response |
|----------|--------|----------|
| `GET /api/v1/scans/{id}` | — | metadata + `findingsCount`, `discoveryUrlsCount` |
| `GET /api/v1/scans/{id}/findings` | `limit`, `offset`, `severity`, `q` | `{ items, total, limit, offset }` |
| `GET /api/v1/scans/{id}/findings/counts` | — | severity → count map (+ `ALL`) |
| `GET /api/v1/scans/{id}/endpoints` | `limit`, `offset`, `q` | paginated URL list |

Legacy scans without DB rows fall back to `findings-final.json` (sliced in handler).

## UI

- Scan detail loads metadata via `getScan`, findings via paginated `getScanFindings` (50/page).
- Endpoints modal: server-side filter + pagination (100/page).

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `DAST_ZAP_FEED_PROBE_MAX` | 500 | Katana→ZAP requestor cap |
| `DAST_HTTPX_BIN` | httpx | httpx binary path |
| `DAST_HTTPX_INPUT_MAX` | 3000 | httpx input URL cap |
| `DAST_HTTPX_DROP_4XX` | off | Drop 404/410 from feed after httpx |
| `DAST_SKIP_ZAP` | off | Skip ZAP step |

## Docker

Сборка и деплой — через `deploy/docker-compose.yml`:

| Сервис | Dockerfile |
|--------|------------|
| server | `Dockerfile.server` |
| worker | `Dockerfile.worker` (katana, httpx, ZAP, nuclei, wapiti) |
| frontend | `web/react/Dockerfile` |

```bash
cd deploy
docker compose build worker server frontend
docker compose up -d
```

## E2E validation (example.com)

Scan `5cdcc574` (shallow: katana depth=1, ZAP 2min):

| Step | Status |
|------|--------|
| katana | SUCCEEDED |
| httpxProbe | SUCCEEDED |
| zapBaseline | SUCCEEDED |
| wapiti | SUCCEEDED |
| nucleiTemplates | SUCCEEDED |

| Metric | Value |
|--------|-------|
| Findings | 20 |
| Discovery URLs | 9 |
| API pagination | `findings?limit=5` → total=20; `endpoints?limit=5` → total=9 |

Artifacts: `httpx-out/httpx-results.jsonl`, `zap-out/zap-report.json`, `reports/discovered_urls.txt`.

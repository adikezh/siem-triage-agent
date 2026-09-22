# SIEM Triage Agent

Community core: NDJSON ingest, deduplication, 15-minute correlation, deterministic scoring, CLI, health API and a non-root container.

Quick start:

    go run . run --file testdata/example.ndjson --db data/triage.db
    go test ./...
    docker compose up --build
    go run . report --db data/triage.db --period 7d --format md --out weekly.md
    go run . rules test --file testdata/example.ndjson --config config.yaml
    go run . feedback export --db data/triage.db --out feedback.jsonl
    go run . apikey create --db data/triage.db --name soc-bot --role analyst

LLM is opt-in. For an OpenAI-compatible endpoint set `--llm-url` and `--llm-model`; use `--llm-api-key-env` to name an environment variable for the key. Without `--llm-url`, the run is rule-only and makes no outbound request.

`docker compose up --build` starts the self-contained demo: it loads `testdata/example.ndjson` into the named SQLite volume and then serves the dashboard/API on port 8080. To reset demo data, run `docker compose down -v`.

If host port 8080 is occupied, use `TRIAGE_PORT=18080 docker compose up --build` (PowerShell: `$env:TRIAGE_PORT=18080; docker compose up --build`).

The server also serves a small HTML dashboard at `/`, OpenAPI JSON at `/openapi.json`, and Prometheus metrics at `/metrics`. API endpoints are `GET /health`, `GET /api/incidents` (optional `severity`, `since`, `limit` filters), `GET /api/incidents/{id}`, `GET /api/stats`, `POST /api/incidents/feedback`, and suppression CRUD under `/api/suppressions`. Telegram and Slack callbacks are accepted at `/api/integrations/telegram/callback` and `/api/integrations/slack/callback`; set `--webhook-secret-env TRIAGE_WEBHOOK_SECRET` to require a shared secret header. Set `--api-key-env TRIAGE_API_KEY` for an environment key, or create a database key with `triage apikey create`; once an active DB key exists, protected API routes require `Authorization: Bearer ...`. Health and metrics remain public for probes. For TLS, pass both `--tls-cert` and `--tls-key`.

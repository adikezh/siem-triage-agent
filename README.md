# SIEM Triage Agent

Community core: NDJSON ingest, deduplication, 15-minute correlation, deterministic scoring, CLI, health API and a non-root container.

Quick start:

    go run . run --file testdata/example.ndjson --db data/triage.db
    go test ./...
    docker compose up --build
    go run . report --db data/triage.db --period 7d --format md --out weekly.md

LLM is opt-in. For an OpenAI-compatible endpoint set `--llm-url` and `--llm-model`; use `--llm-api-key-env` to name an environment variable for the key. Without `--llm-url`, the run is rule-only and makes no outbound request.

The current release intentionally has no outbound network calls and no LLM fallback. Production integrations, persistence, auth, UI and reports remain tracked in TODO.md and are not claimed complete.

The server also serves a small HTML dashboard at `/` and Prometheus metrics at `/metrics`. API endpoints are `GET /health`, `GET /api/incidents`, `GET /api/incidents/{id}`, `GET /api/stats`, and `POST /api/incidents/feedback`. Set `--api-key-env TRIAGE_API_KEY` to protect incident endpoints with `Authorization: Bearer ...`; health and metrics remain public for probes.

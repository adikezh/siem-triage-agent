# SIEM Triage Agent

Community core: NDJSON ingest, deduplication, 15-minute correlation, deterministic scoring, CLI, health API and a non-root container.

Quick start:

    go run . run --file testdata/example.ndjson --db data/triage.db
    go test ./...
    docker compose up --build

The current release intentionally has no outbound network calls and no LLM fallback. Production integrations, persistence, auth, UI and reports remain tracked in TODO.md and are not claimed complete.

The local API exposes `GET /health`, `GET /api/incidents`, and `POST /api/incidents/feedback`. It is intentionally unauthenticated for the demo and must not be exposed to an untrusted network.

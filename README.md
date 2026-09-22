# SIEM Triage Agent

Community core: NDJSON ingest, deduplication, 15-minute correlation, deterministic scoring, CLI, health API and a non-root container.

Quick start:

    go run . run --file testdata/example.ndjson
    go test ./...
    docker compose up --build

The current release intentionally has no outbound network calls and no LLM fallback. Production integrations, persistence, auth, UI and reports remain tracked in TODO.md and are not claimed complete.

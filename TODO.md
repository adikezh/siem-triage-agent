# Delivery backlog

- [~] SQLite WAL store saves normalized alerts and incidents, with source cursor, idempotent outbox and retry/backoff dispatcher; production sender wiring remains.
- [~] Wazuh/OpenSearch-compatible search-after client and source→process→cursor→outbox worker are present; normalized domain ingest and live Wazuh proof remain.
- [~] YAML config and suppression decisions are wired into offline ingest; DB-backed suppression CRUD/API and created-by/created-at audit fields are present, while applying DB rules in ingest and immutable audit hashing remain.
- [~] YAML asset inventory and local IOC enrichment are wired into offline scoring; history/GeoIP/AbuseIPDB/VT enrichment remains.
- [x] Deterministic scoring formula, table tests, feedback FP-history deduction, JSONL feedback export and eval precision/recall command are present.
- [~] PII redaction, prompt builder, OpenAI-compatible provider, strict output/action validation, provider fallback, budget guard, triage merge engine, versioned prompts, CLI opt-in runtime path and LLM trace schema are present; persistent budget/config wiring and non-OpenAI providers remain.
- [x] Generic HMAC webhook, Telegram Bot API, Slack Block Kit, Jira REST, IRIS and TheHive senders plus Wazuh field normalizer are present and tested.
- [~] Optional API-key Bearer authentication uses digest comparison, optional TLS protects the server, and OpenAPI JSON plus suppression CRUD are exposed; markdown reports and basic dashboard work, while DB-backed key rotation, RBAC, filters and PDF/DOCX remain.
- [~] Hosted CI, Docker build, Compose writable SQLite volume, container `/health`, govulncheck/SBOM CI steps, benchmark and basic Prometheus metrics are configured/proven locally; hosted security-artifact run and real SOC demo evidence remain.

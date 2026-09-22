# Delivery backlog

- [~] SQLite WAL store, source cursor, idempotent outbox and retry/backoff dispatcher are present and tested; production sender wiring remains.
- [~] Wazuh/OpenSearch-compatible search-after client and source→process→cursor→outbox worker are present; normalized domain ingest and live Wazuh proof remain.
- [~] YAML config and suppression decisions are wired into offline ingest; persistent suppression audit chain and UI/DB-managed rules remain.
- [ ] Asset/history/GeoIP/threat-intel enrichment.
- [x] Deterministic scoring formula and table tests (history-frequency input remains to be wired from feedback store).
- [~] PII redaction, prompt builder, OpenAI-compatible provider, strict output/action validation, provider fallback, budget guard, triage merge engine, versioned prompts, CLI opt-in runtime path and LLM trace schema are present; persistent budget/config wiring and non-OpenAI providers remain.
- [~] Generic HMAC webhook sender and Wazuh field normalizer are present and tested; Telegram/Slack/IRIS/TheHive/Jira adapters remain.
- [~] Optional API-key Bearer authentication protects incident/feedback endpoints; RBAC, key hashing/rotation, UI and reports remain.
- [ ] Hosted CI, govulncheck, SBOM, load test and real SOC demo evidence.

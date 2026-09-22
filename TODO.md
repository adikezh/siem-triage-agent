# Delivery backlog

- [x] SQLite WAL store and schema migration; cursor/outbox still pending.
- [~] Wazuh/OpenSearch-compatible search-after client with cursor test is present; persistent cursor, normalized ingest wiring and live Wazuh proof remain.
- [~] YAML config and suppression decisions are wired into offline ingest; persistent suppression audit chain and UI/DB-managed rules remain.
- [ ] Asset/history/GeoIP/threat-intel enrichment.
- [x] Deterministic scoring formula and table tests (history-frequency input remains to be wired from feedback store).
- [~] PII redaction, prompt builder, OpenAI-compatible provider, strict output/action validation, provider fallback, budget guard, triage merge engine, versioned prompts, CLI opt-in runtime path and LLM trace schema are present; persistent budget/config wiring and non-OpenAI providers remain.
- [ ] Telegram/Slack/webhook/IRIS/TheHive/Jira adapters.
- [ ] Authenticated REST API, RBAC, UI and reports (demo read/feedback API exists; authentication is still pending).
- [ ] Hosted CI, govulncheck, SBOM, load test and real SOC demo evidence.

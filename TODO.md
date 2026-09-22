# Delivery backlog

- [x] SQLite WAL store and schema migration; cursor/outbox still pending.
- [ ] Wazuh/OpenSearch polling and restart proof.
- [~] YAML config and suppression decisions are wired into offline ingest; persistent suppression audit chain and UI/DB-managed rules remain.
- [ ] Asset/history/GeoIP/threat-intel enrichment.
- [x] Deterministic scoring formula and table tests (history-frequency input remains to be wired from feedback store).
- [~] PII redaction, prompt builder, OpenAI-compatible provider, strict output/action validation, provider fallback, budget guard, triage merge engine and LLM trace schema are present; prompt files and CLI/runtime wiring remain.
- [ ] Telegram/Slack/webhook/IRIS/TheHive/Jira adapters.
- [ ] Authenticated REST API, RBAC, UI and reports (demo read/feedback API exists; authentication is still pending).
- [ ] Hosted CI, govulncheck, SBOM, load test and real SOC demo evidence.

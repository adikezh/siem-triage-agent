# Delivery backlog

- [~] SQLite WAL store saves normalized alerts and incidents, with automatic/explicit `migrate up` schema initialization, source cursor, idempotent outbox, retry/backoff dispatcher, configurable alert/LLM retention pruning, optional live webhook sender wiring, and bounded HTTP drain and tracked worker shutdown.
- [~] Wazuh/OpenSearch-compatible search-after client, generic Elastic/OpenSearch field-mapped client, optional continuous `serve --source-url` polling with asset/IOC enrichment, page/cross-page alert→incident correlation with configurable grouping overrides, source→process→cursor→outbox worker, and optional notifications are present; external source proof remains.
- [~] YAML/CSV asset inventory (`assets import`), RFC1918/configured internal subnet detection, and local IOC enrichment are wired into offline/live scoring; opt-in AbuseIPDB/VirusTotal IP clients have 5–6s timeouts and a SQLite-backed 24h cache, local MaxMind GeoLite2 country lookup is available for LLM context, 30-day fingerprint recurrence and the last five same-fingerprint or same-agent/source incidents/verdicts are available.
- [~] YAML and DB suppression decisions are wired into offline and live ingest using the effective configured grouping fingerprint; DB/API rules support fingerprint or structured Alert matching (rule, agent, groups, description regex, src_ip CIDR/glob), created-by/created-at audit fields, tamper-evident audit hashing, and a three-FP suppression suggestion in the feedback API.
- [~] Deterministic scoring formula, table tests, feedback FP-history deduction, JSONL feedback export and eval precision/recall command are present.
- [x] Scenario fixtures for brute-force, lateral movement, and FIM noise are checked in CI for expected incident counts and severity.
- [~] Correlation uses map-based fingerprint grouping and O(n log n) timestamp ordering; the current local 100k-alert benchmark is 97.9 ms on Windows amd64 (Intel Ultra 5 225H), while the exact 500 alerts/s ingest target still needs a representative production dataset and hosted hardware proof.
- [~] PII redaction, language-aware RU/EN/KK prompt builder, OpenAI-compatible/Ollama/Anthropic providers, strict output/action validation, configured provider fallback, in-memory budget guard, triage merge engine, checked-in prompt examples (runtime template loading still pending), config-selected providers, offline and live runtime paths, and LLM trace persistence are present.
- [~] Generic HMAC webhook, Telegram Bot API, Slack Block Kit, Jira REST, IRIS and TheHive senders are configuration-wired through a multi-channel idempotent outbox with retry; Wazuh fields and Telegram/Slack callbacks are tested, including native signature verification and TP/FP/Ack/Open button cards. Provider-specific production credentials and endpoint behavior remain deployment gates.
- [~] API and browser authentication use hashed DB keys or a scoped environment key. Browser login, TP/FP/Ack forms, fingerprint-prefilled suppression suggestions, create/delete forms, server-side viewer/analyst/admin enforcement and atomic mutation/audit writes are implemented. The embedded templ/htmx/Tailwind UI has EN/RU/KK labels, severity/since/limit filters and 24h/7d/all-time incident dashboards. FP rate/MTTA/LLM/outbox aggregates are labelled all-time; token accounting and alert timeline remain open. Markdown/PDF/DOCX reports work with day/week/month aliases.
- [~] Hosted CI (tests, vet, build, golangci-lint, Helm lint, govulncheck, SBOM), Docker build, Compose writable SQLite volume, self-contained demo loader/server, container `/health`, Helm chart, GoReleaser release workflow, tag `v0.1.3` publication with archives/deb/rpm/GHCR/SBOM, Prometheus incident/LLM/feedback/outbox metrics, and a GitHub Pages product page workflow are present; real SOC demo evidence, live-provider evidence, and production rollout gates remain.

## Reliability slice completed and verified on 2026-10-02

- [x] Inclusive timestamp pagination, full lossless cursor restore, cold-start
  date_nanos query, and rejection of partial/missing-sort responses.
- [x] Atomic alert/incident/trace/outbox/checkpoint page commit, durable replay
  deduplication, rollback on injected write failures and stale-writer detection.
- [x] Independent outbox delivery, bounded exponential retries for 24 hours,
  explicit failed metrics and propagation of delivery-status write errors.
- [x] Built-binary delivery with unavailable/absent SIEM and SIGTERM shutdown;
  real two-shard OpenSearch pagination/restart and Linux race tests.
- [x] Isolated Compose smoke cleanup that does not delete an existing demo's
  volume. Hosted CI is configured to run the real-source and process tests.

## Required implementation backlog (not external-only gates)

- [ ] Finish the specified Alert/Incident model: raw retention, stable IDs,
  incident_alerts links, statuses and timeline; avoid cross-index ID collisions.
- [ ] Wire the full YAML source configuration, generic continuous source and
  stdin paths; define bounded backpressure, source identity and late-arrival
  reconciliation instead of assuming monotonic event time.
- [ ] Complete configurable scoring and live recurrence/TI context parity.
- [ ] Load actual versioned prompt files at runtime; harden untrusted-data
  framing, preserve local reversible PII mappings and provider privacy policy.
- [ ] Persist LLM hourly/daily budgets across restart; token/cost accounting,
  configurable token caps and budget-exhaustion warning.
- [ ] Verify and finish IRIS case/IOC/timeline/status, TheHive alert-to-case,
  Jira field templates, Telegram callback limits/Open links and native Slack
  callback payloads. Mock tests do not establish vendor API compatibility.
- [x] Browser-visible detail/feedback/suppression creation, slash-containing
  incident ID routing, browser authentication, CSRF protection, write-role
  enforcement and 24h/7d incident dashboard. Automated and real browser checks
  cover the completed flows; this does not establish full UI/TZ acceptance.
- [ ] Finish alert timeline and enrichment presentation using the complete
  normalized model; add persisted LLM token consumption to the dashboard.
- [ ] Implement and test Pro PostgreSQL, OIDC and regulatory report templates;
  these are absent implementations, not credential-only acceptance.
- [ ] Verify exact TZ coverage/performance/resource gates and full demo with
  local LLM/generator; browser acceptance is still required before v1.0.
- [ ] Customer source/provider validation, operational recovery/deployment and
  SOC analyst demonstration (external acceptance, separately evidenced).

Multi-tenant support belongs to the TZ's post-v1 roadmap, not the v1 DoD.

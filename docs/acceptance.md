# Acceptance evidence

This document separates repository-verified behavior from deployment-dependent gates.

## Repository checks

Run from the repository root:

```powershell
go test ./...
go vet ./...
go test -run '^$' -bench '^BenchmarkGroup100k$' -benchtime=1x -count=1
.\scripts\compose-smoke.ps1
```

The Compose smoke script builds the distroless image, starts the demo with a
writable SQLite volume, checks `/health`, checks the server-rendered `/stats`
dashboard, verifies that at least one demo incident was loaded, and removes the
temporary containers, network, and volume in `finally`.

Hosted `.github/workflows/ci.yml` additionally runs race tests, build, lint,
Helm lint, `govulncheck`, SBOM generation, and the Compose demo smoke path.

## Implemented core scope

The repository contains the SQLite/WAL store, file/Wazuh/generic ingest,
cursor and outbox retry, grouping and suppression rules, asset/IOC/GeoIP and
history enrichment, deterministic and LLM triage, feedback/eval, API-key RBAC,
dashboard/API/metrics, reports, configured notification channels, Docker and
Helm packaging.

## Deployment-dependent gates

These cannot be proven from the repository alone and must be run against the
customer environment before a production decision:

- Wazuh/OpenSearch or Elastic endpoint behavior with representative data;
- real Telegram, Slack, IRIS, TheHive and Jira credentials/endpoints;
- production hardware proof of the 500-alerts/second target;
- backup/restore, failure recovery, retention and multi-worker rollout;
- Pro-only PostgreSQL, OIDC and multi-tenancy features;
- customer SOC demonstration and recorded analyst feedback.

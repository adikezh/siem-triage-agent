---
layout: default
title: SIEM Triage Agent
---

# SIEM Triage Agent

Turn noisy SIEM alerts into explainable, reviewable incidents.

## The problem

SOC L1 teams receive thousands of alerts every day. Rule severity alone does not capture asset criticality, threat-intelligence context, recurrence, or analyst feedback.

## The solution

SIEM Triage Agent is a self-hosted Go service and CLI that:

- ingests NDJSON and Wazuh/OpenSearch alerts;
- correlates duplicates into incidents;
- enriches assets, IOC, GeoIP, history, and threat intelligence;
- scores incidents deterministically before optional LLM analysis;
- sends reviewable cards to Telegram, Slack, generic webhooks, Jira, IRIS, and TheHive;
- records TP/FP/Ack feedback and tamper-evident audit events;
- exposes a dashboard, REST API, OpenAPI, Prometheus metrics, and reports.

## Five-minute demo

```bash
git clone https://github.com/adikezh/siem-triage-agent.git
cd siem-triage-agent
docker compose up --build
```

Open `http://localhost:8080`. The demo loads example alerts into SQLite and serves the dashboard, API, and metrics endpoint.

## Community and Pro

| Community | Pro / enterprise |
| --- | --- |
| Apache-2.0 core | Commercial support and deployment |
| SQLite | PostgreSQL and multi-tenant deployment |
| Wazuh/OpenSearch and NDJSON | OIDC/SSO and extended RBAC |
| Rule-only or configured LLM providers | Regulatory report templates and integrations |
| Telegram, Slack, webhook | MSSP-scale operations and custom tuning |

## Evidence and documentation

- [README and quick start](https://github.com/adikezh/siem-triage-agent)
- [release artifacts](https://github.com/adikezh/siem-triage-agent/releases)
- [delivery backlog and verification boundaries](https://github.com/adikezh/siem-triage-agent/blob/master/TODO.md)

The community core is licensed under [Apache-2.0](https://github.com/adikezh/siem-triage-agent/blob/master/LICENSE).

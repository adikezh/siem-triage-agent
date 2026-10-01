# Acceptance evidence

The complete TZ remains the acceptance scope. Green checks establish the
behaviors below, not completion of every v1.0 requirement. Implementation gaps
and external/customer evidence are separate; neither is hidden behind
"Community core complete".

## Reproduce repository checks

Run from the repository root:

```powershell
go test ./... -count=1
go vet ./...
go test -run '^$' -bench '^BenchmarkGroup100k$' -benchtime=1x -count=1
.\scripts\compose-smoke.ps1
```

The smoke script uses a fresh, uniquely named Compose project. It waits for
health, checks the SSR dashboard and seeded incidents, removes only its own
containers/network/volume, and restores TRIAGE_PORT. It does not remove an
existing demo's data.

On Linux, additionally run:

```sh
TRIAGE_RUNTIME_TEST=1 go test -race ./... -count=1
TRIAGE_TEST_OPENSEARCH_URL=http://127.0.0.1:19203 go test ./internal/ingest -run TestOpenSearchEqualTimestampPaginationAndRestart -v -count=1
```

The OpenSearch test creates and deletes only a uniquely named
triage-integration-* fixture index. Point it at a disposable test instance.
Hosted CI runs a pinned OpenSearch 2.19.4 service, enables both integration
tests, and also performs build, lint, Helm lint, vulnerability and SBOM checks.

## Reliability verified on 2026-10-02

- Timestamp range is inclusive; search_after supplies the exclusive tie-breaker.
  Wazuh and generic clients retain equal-timestamp events across page boundaries.
- Numeric sort values are decoded without float64 rounding and restored after
  restart. New sources do not send a year-0001 date_nanos range.
- Partial/timed-out search results and missing sort keys fail without advancing
  the checkpoint.
- Durable alert IDs and within-page duplicates are excluded before correlation.
- SQLite commits alerts (including suppressed alerts), incidents, model traces,
  notifications and the cursor in one transaction. Injected outbox and cursor
  write failures roll back every effect; retry and restart preserve the batch.
- The transaction is opened only after enrichment/model work. An optimistic
  checkpoint and unique alert guard reject stale/replayed writers.
- Delivery runs independently of ingest, including when no SIEM is configured.
  Built-binary tests cover unavailable SIEM, durable delivery and SIGTERM exit.
- Exponential retry is capped at one hour between attempts and expires after
  24 hours by default. Failed deliveries are visible in API stats, dashboard
  and Prometheus metrics; legacy year-deferred records also expire.
- A successful recipient response is not counted as durably sent if recording
  that result fails. HTTP shutdown drains before SQLite and GeoIP are closed.

These tests passed locally with the race detector, a real two-shard OpenSearch
index, and built-process tests. This is local evidence; hosted CI results must
be checked for the exact pushed commit.

## Source and delivery constraints

The tie-breaker must be unique within the queried index pattern and mapped as
a sortable keyword/numeric field with doc_values. The default is id; configure
serve --source-tiebreaker event_id (or id.keyword for a text mapping) as needed.
_id is explicitly rejected because OpenSearch/Elasticsearch do not allow
sorting on it. [OpenSearch restriction](https://docs.opensearch.org/latest/field-types/metadata-fields/id/).

The source must supply the configured timestamp and stable sort values.
Late arrivals behind the checkpoint and changing source identity/mappings need
a separately designed overlap/reconciliation policy. This slice does not
claim to solve arbitrary event-time reordering, multi-index ID collisions,
or distributed multi-worker incident updates.

The outbox guarantees one local record per incident/channel and at-least-once
delivery, not exactly-once remote side effects: a crash after remote acceptance
but before the local sent update can cause a resend. Provider-specific
idempotency/update semantics still need verification.

## Remaining implementation work

See TODO.md. Open items include the complete normalized/raw model and incident
timeline, configuration-driven generic runtime/scoring, prompt-template and
PII-mapping persistence, durable LLM budget/token accounting and warnings,
real provider API semantics, alert timeline and complete enrichment views,
and Pro PostgreSQL/OIDC/regulatory templates. They are code work, not merely
missing credentials. Multi-tenancy is a post-v1 roadmap item in the TZ, not
a v1 acceptance gate.

## External acceptance

Representative customer-source data and hardware, real notification/provider
credentials, operational deployment/backup-restore evidence, and a SOC
demonstration with recorded analyst feedback remain external evidence.
Repository tests alone do not close those gates.

## Browser workflow verified on 2026-10-02

Browser checks used an isolated local fixture with separate synthetic viewer
and analyst keys; automated HTTP tests additionally cover admin. The browser
opened a slash-containing incident ID, submitted
three FP verdicts, followed the resulting suggestion and saved a prefilled
suppression with the authenticated analyst as its author. EN, RU and KK labels
were checked. At a 390-pixel viewport the detail page fit the viewport and the
viewer had no mutation controls. Admin deletion and direct forbidden writes
are covered by automated HTTP tests, not claimed as manual browser deletion.

The UI uses templ, htmx and compiled Tailwind CSS embedded in the Go binary;
ordinary builds need no Node runtime or CDN. CI regenerates the committed
templates/assets and checks for a diff. htmx evaluation, embedded script
execution and local history storage are disabled.

Authentication is rechecked on every request. Creating a first key protects
existing handlers; revoking the last key does not restore demo mode. Browser
sessions contain only an opaque identifier, expire after eight hours, are
invalidated by logout/server restart, and resolve the current key role and
revocation state from the database. Tests cover CSRF, Origin checks, cookie
flags, session capacity, proxy HTTPS origins and failed authentication storage.

Viewer can read; analyst/admin can give feedback and create suppressions;
only admin can delete them. The server derives audit identity from the key.
Feedback and rule writes commit with their audit record or roll back together;
injected audit failures and concurrent hash-chain writers are tested. A rule
requires a nonempty match and reason, valid regex/CIDR/glob and a valid future
expiration when supplied. Dashboard incident windows are 24h/7d/all-time;
feedback, MTTA and delivery totals are explicitly all-time, not windowed values.

Alert timeline, full enrichment presentation and persisted token consumption
remain implementation work. This browser slice is not v1.0 acceptance, a
penetration test, or evidence of a real SOC/customer deployment.

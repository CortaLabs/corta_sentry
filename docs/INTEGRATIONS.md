# Integration surfaces

CortaSentry is implemented in Go, but integrations do not need to be. Its supported boundaries use language-neutral contracts:

- REST/JSON for assets, observations, findings, changes, jobs, rules, audit, scan submission, and JSONL export.
- MCP stdio for Codex, Claude, and any compatible agent harness. Mutating and active tools remain separately gated.
- Prometheus text exposition at `/metrics`.
- `cortasentry.observation.v1` JSONL for streaming into Python, jq, data lakes, SIEM pipelines, or message adapters.
- SQLite WAL for local durability and backup. External software should use the API/export contract rather than writing the database.
- Structured JSON process logs with request, job, and outcome context where applicable.

There is no Python SDK yet because ordinary HTTP clients and JSONL cover the current contract without duplicating domain rules. A future SDK should be generated or kept thin: scope authorization, identity resolution, and finding-state ceilings must remain server-authoritative.

Telemetry is local-only and has no phone-home analytics. Current Prometheus families cover scans, probes, errors, persisted observations by source, created assets, findings, queue depth, job duration, and rule evaluations. Process/Go runtime metrics are also exposed. The next telemetry hardening phase should initialize gauges from durable database state after restart, add HTTP latency/status histograms, track collector truncation and authorization denials, and publish passive-connection snapshot counts without high-cardinality remote-IP labels.

# Implementation log

## 2026-07-12

- Inspected the clean repository (README only), applicable parent policy, Go 1.22.2, and Node/npm environment.
- Chose a stdlib-first modular monolith, pure-Go modernc SQLite, typed YAML rules, React/Vite, and a capability-style authorized dialer.
- Implemented domain models, migration schema, WAL/foreign-key/busy-timeout checks, immutable observation/audit triggers, persistence, and recoverable job leases.
- Implemented strict config and scope. Review caught and fixed unsafe IPv6 bind parsing, missing snake_case YAML tags, and mapped-prefix underflow.
- Implemented bounded TCP/banner/HTTP/TLS, shell-free neighbors, finite mDNS/SSDP, loopback fixtures, resolver, rule engine, finding ceilings, changes, and importers.
- Implemented bootstrap/token rotation, hashed tokens/sessions, CSRF, request/rate limits, audited REST API, embedded UI, CLI, installer, Docker/CI/docs.
- First compile found a collector/discovery import cycle; replaced concrete dependencies with narrow dial interfaces.
- First backend test found migration replay on reopen; fixed version preflight. Sanitization test boundary corrected.
- Frontend audit initially found patched-development-tool advisories in Vite/Vitest; upgraded lockfile and verified zero npm advisories.
- Removed unused jsdom after its deprecated transitive package warning; regenerated a 95-package lock with zero advisories.
- Ran the fixture demo: two states produced 16 observations, four stable assets, fingerprint candidates, first-seen events, and one changing-title event; reopening through CLI preserved assets.

Known limitations are tracked in README and SECURITY_REVIEW rather than hidden behind completion language.

- Resumed the hardening phase after review: replaced direct scan goroutines with bounded leased workers, cancellation polling, restart recovery, queue limits, progress, and idempotent MCP scan submission.
- Added an official-SDK MCP 2025-11-25 stdio adapter with 12 read/resource operations and six separately gated mutations. Registered and connected it in local Codex and Claude Code harnesses.
- Reworked endpoint ingestion into observation batches so TCP, HTTP, TLS, and banners resolve to one asset; added recent address/service-set continuity without allowing IP-only merges.
- Wired advisory correlation into scan jobs and imported evidence into the same identity, fingerprint, finding, and change derivation pipeline.
- Added change evidence for new services, certificate fingerprints, classification transitions, and HTTP titles. Removal/disappearance grace reconciliation remains a documented limitation.
- Replaced the frontend with a responsive operations console based on an ImageGen design study, using only real API data. Added automatic session restoration and direct `admin.token` file selection on the login screen.
- Upgraded the backend baseline to Go 1.25 for the current official MCP Go SDK and added Codex/Claude MCP configuration examples to the installer.

The earlier verification record above describes the first vertical slice. A fresh final validation record is added only after the resumed suite completes.

- Found a live credential recovery mismatch caused by relative config paths resolving against the launch directory. Fixed database, data, and rule path resolution to anchor at the configuration file and added a regression test.
- Resumed validation checkpoint executed `make fmt`, `make lint`, `make test`, `make test-race`, `make build`, `make smoke`, `git diff --check`, and `npm audit --audit-level=high`: 35 Go tests passed, one frontend test file passed, race and vet passed, the production frontend and three binaries built, smoke passed, and npm reported zero vulnerabilities.
- Executed the corrected `./install.sh --prefix /usr/local`. It built and tested without privilege, requested elevation only for the final copy, then installed the three binaries, device/service/advisory rules, and all server/Codex/Claude example configs. `/usr/local/bin/cortasentry version` returned `0.1.0`.
- Restarted the validated embedded console at `127.0.0.1:8088`; direct login, session refresh, overview API, and persisted fixture data were verified. Codex reported the MCP registration enabled and Claude Code reported it connected.
- Independent review rejected readiness on additional acceptance gaps. Fixed its three immediate safety defects: custom-config initialization path divergence, nonterminal queued cancellation, and false merges when new or partially contradictory strong identifiers accompanied weak continuity. Added regression tests for each.
- Expanded asset detail storage/API/UI with identifiers, historical addresses, supporting/conflicting observation links, fingerprint candidate score breakdowns, and confirmed/audited manual merge controls. Request IDs now enter request context, structured request logs, and mutation audit events.
- Frontend tests now exercise scan input normalization/bounds and deterministic domain formatting rather than asserting a trivial string property. The normal-workflow local discovery, complete change/grace reconciliation, and remaining durable job handlers are still open acceptance work.
- Fixed the Scans page crash by making empty durable-job collections encode as `[]` and retaining a defensive UI array guard. Verified the live preview remains fail-closed while active probing is disabled.
- Added the `cortasentry.observation.v1` JSON Schema, REST/CLI JSONL exports, interoperability documentation, and a bounded Linux `ss` passive connection snapshot collector. A live snapshot produced 239 immutable `host_connection` records; validation then corrected the model so remote endpoints remain observations rather than automatically becoming managed assets.
- Moved observation Prometheus accounting to the central persistence boundary so scans, imports, and passive snapshots use one counter path. Documented current restart/gauge and HTTP-metric gaps honestly.
- Fixed source-build rule discovery outside the checkout by recognizing both installed `share/cortasentry/rules` and source `bin/../rules` layouts. Recreated a clean six-asset live demo database and verified `/api/v1/jobs` returns `[]`.
- Follow-up hostile review confirmed scope enforcement and bounded HTTP behavior, then identified audit noise and an underspecified resolver reason. Added schema migration 3 with policy-decision phases: successful preflight allows remain durable operational traces, while denials and execution decisions remain primary audit events. Fail-closed behavior was preserved and regression-tested.
- Resolver results now record exact `strong_identifier_match`, `continuity_match`, `no_strong_identifier_match`, or `strong_identifier_conflict` paths and evidence. Tests cover exact strong-match explanation, continuity explanation, new-strong-ID reuse protection, and partial strong-ID conflict behavior.
- Hostile control-plane review found no direct authentication or scope bypass. It identified unsafe-cookie/public-bind coupling, token-file rewrite/crash behavior, missing Host/Origin validation, GET-based CSRF refresh, globally exhaustible login throttling, incomplete auth attribution, and sparse MCP gate coverage.
- Hardened those boundaries with exact allowed Hosts, separate non-loopback cookie acknowledgment, same-origin/fetch-metadata enforcement, POST session refresh, per-source bounded login buckets, audited login denial/request IDs, durable token/session actor IDs, staged atomic 0600 token replacement, 0700 data/0600 database repair, audit-error propagation, and an all-mutation MCP gate matrix.

# Architecture

CortaSentry is a modular monolith. `cmd/cortasentry` composes domain packages; package boundaries provide future sensor and Council seams without introducing a broker today.

## Evidence pipeline

Targets enter through `internal/scope`. Only normalized IP/CIDR targets are accepted. A preflight checks host/port cardinality; `AuthorizedDialer` rechecks every exact IP and port immediately before a normal TCP connection, then applies global and per-host rates and deadlines. Collectors report bounded facts, never product or vulnerability declarations. `internal/observation` removes sensitive headers, printable-bounds untrusted text, and computes digests. SQLite triggers reject observation update/delete.

`internal/assets` attaches evidence only on agreeing strong identifiers. IP, hostname, or shared certificates alone never cause a merge. Insufficient evidence creates a safe duplicate. Relationships record resolver reason/version and conflicts remain explicit. Resolver reasons name the exact `strong_identifier_match`, `continuity_match`, `no_strong_identifier_match`, or `strong_identifier_conflict` path; continuity includes its address, service-set digest, and 30-minute window. A partially matching strong-identifier set creates a conflict asset pending operator review. Manual merges are authenticated, transactional, audited, and reject conflicting strong identifier kinds.

`internal/fingerprint` strictly loads typed YAML, compiles RE2 expressions once, gates required predicates, caps a source's contribution, applies negative evidence and source-diversity/specificity bonuses, clamps to 0–1, and persists candidate breakdowns. Scores are identification scores, not calibrated probabilities. Close candidates are ambiguous.

Advisory correlation enforces evidence ceilings: vendor-only is potential; product evidence can become likely; confirmed affected firmware can become version-confirmed; only a separate safe validator can become safely validated. Imports never bypass these ceilings.

Changes store previous/current state and triggering observations under a dedupe key. The demo proves first-seen and HTTP-title change paths. Durable jobs use SQLite leases and recover expired claims. The API and embedded UI read the same store.

## Trust boundaries and seams

- Network egress capability: scope engine plus authorized dialer.
- Authorization records: preflight and execution both evaluate policy and persist decisions. Successful preflight allows stay in the operational `policy_decisions` ledger; preflight denials and all execution decisions also become primary `scope.decision` audit events. Persistence failure denies authorization.
- Untrusted inputs: banners, HTTP, TLS metadata, UDP discovery, imports, and YAML rules.
- Operator actions: authenticated API/CLI plus immutable audit events.
- Storage: narrow domain operations over explicit SQL; PostgreSQL can implement the same use cases later.
- Domain events: event names are modeled for later in-process publication and Council consumption; no external event bus exists.
- Future sensors: the sensor binary is intentionally non-enrolling until authenticated transport and signed batches are designed.

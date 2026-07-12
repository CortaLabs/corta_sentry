# Security review — 2026-07-12

This adversarial review covered the initial v0.1 implementation and was repeated after fixes.

## Reviewed and fixed

- Scope/SSRF: canonical `netip` parsing and `Unmap`; mapped-prefix underflow rejected; allow then deny; public/multicast/unspecified/limited-broadcast rejection; preflight budgets; execute-time recheck; pinned HTTP dialing; proxy/decompression/redirect disabled; hostname targets unsupported.
- Public exposure: strict `net.SplitHostPort` parsing fixed an IPv6/hostname bind-validation bypass. Loopback is default and non-loopback requires explicit unsafe override.
- Shell/argument injection: neighbor commands use `exec.CommandContext` with fixed executable/arguments. Nmap execution is not implemented. Imports never execute input.
- Unbounded work: worker count, host/port counts, connection rates, deadlines, header/body/banner/certificate bytes, import totals/records, UDP packets, rules/predicates/regexes, and pagination are bounded.
- Evidence/secrets: authorization/cookie headers are removed case-insensitively; untrusted excerpts are printable-bounded; token material is not logged; raw tokens are hash-only in SQLite and secret files are 0600.
- Authentication: protected API resources reject anonymous users; browser mutations require CSRF; sessions expire; rotation revokes tokens/sessions; login and scan requests are rate-limited; JSON bodies are bounded and strict.
- Storage/SQL: explicit parameterized SQL, WAL, foreign keys, busy timeout, forward version checks, transactional migration, reopen tests, immutable observation/audit triggers, leased durable workers, cancellation polling, bounded queue growth, idempotent MCP scan submission, and expired-lease recovery.
- Identity/claims: IP, hostname, and certificate evidence alone never merges; conflicting strong identifiers create a safe conflict asset; manual merges reject conflicting strong kinds. Advisory state ceilings prevent vendor-family overclaims.
- XSS/parser abuse: UI does not use raw HTML; CSP denies inline/script origins; imports are byte-capped before decode; XML external resolution is absent from Go's decoder; YAML fields/operators are allowlisted and RE2 compiles once.
- Supply chain: frontend advisory audit was run; Vite/Vitest were upgraded to patched releases and the lock audit then reported zero vulnerabilities.

## Residual limitations

- Active job cancellation is polled at the configured job interval, not instant at the individual socket syscall boundary. Socket deadlines and context cancellation bound that delay.
- Jobs restart from their bounded payload after an expired lease; individual completed probe checkpoints are not persisted, so a crash may repeat already completed non-destructive connections. Immutable observations and change deduplication tolerate the repeat, but exact-once probing is not claimed.
- Live scan observations without strong identifiers use same-endpoint batching and a 30-minute address plus service-set continuity window. This is deliberately conservative; DHCP reuse inside that window with an identical service set can still create ambiguity and requires operator review.
- When any strong identifier is supplied, weak continuity is disabled unless every supplied strong identifier agrees with the same existing asset. Unmatched strong identity creates a duplicate; partial/multiple agreement creates an explicit conflict asset.
- mDNS/SSDP collectors are bounded but not wired into normal scheduled scans. Directed broadcast exclusion is enforced during CIDR expansion; an explicitly listed address that is a subnet broadcast cannot be recognized without interface-prefix context.
- Secure cookies are an explicit deployment setting separate from the non-loopback bind override. Operators terminating TLS must enable it and enforce HTTPS/trusted proxy configuration externally; the application does not terminate TLS itself.
- Metrics include probe, observation, asset, scan, error, queue, job-duration, finding, and rule-evaluation families, but some labels remain coarse. Audit event insertion is transactionally coupled to scope decisions but not every associated domain mutation.
- New-service, certificate, classification, and HTTP-title changes are derived. Service removal, asset disappearance, IP retirement, firmware change, and finding-remediation grace reconciliation are not complete.
- No cryptographic rule-bundle signature, database encryption, remote sensor trust, PostgreSQL, or HA mode exists.

These are meaningful production-readiness limitations. The recommended next phase is durable leased scan execution with cancellation polling, richer conservative identity ingestion, comprehensive state snapshots/grace logic, and full domain metrics before remote sensors or Council integration.

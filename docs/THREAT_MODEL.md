# Threat model

## Protected assets

Authorization policy, administrator tokens/sessions, raw evidence, asset identity, findings, audit history, rules, and database availability.

## Threats and controls

- Malicious devices may stall, return binary/huge content, secret-shaped headers, redirects, malformed TLS, or HTML/JS. Collectors use deadlines and byte/header/certificate caps, disable decompression and redirects, sanitize before persistence, and the UI uses React text rendering plus CSP.
- Scope bypass attempts may use mapped IPv6, malformed CIDR, public addresses, multicast, broadcast, denied subnets, ports, hostnames, or redirects. Inputs normalize with `netip`, deny wins after allow, public targets require explicit policy, hostnames are unsupported, and HTTP dialing is pinned to the authorized IP/port.
- Untrusted imports may be huge or malformed. Total and per-record limits precede XML/JSON decoding; imported content is never executed. Nuclei claims remain unverified observations.
- Unauthorized users face bearer/session authentication, high-entropy hashed tokens, expiring opaque sessions, CSRF on cookie mutations, request bounds, and login/scan creation rates. Localhost is the default bind.
- A compromised sensor is outside v0.1 because remote enrollment is disabled. Future sensors require mutual authentication, scoped assignments, replay controls, and signed batches.
- Rule tampering can cause false classifications. Rules are local, strictly typed, bounded, digested, compiled atomically, and cannot execute code/read files/network.
- Database theft exposes sanitized evidence and token hashes but not bootstrap tokens. Operators must restrict data-directory access and encrypt disks/backups.
- Denial of service is limited with scan cardinality, worker, queue, rate, deadline, body, and parser budgets. SQLite still has single-node capacity limits.
- False identification and vulnerability claims are controlled by candidate retention, ambiguity, strong-ID rules, evidence references, and finding-state ceilings.

# Local connection visibility

`cortasentry connections snapshot` is the first passive host-telemetry surface. On Linux it executes `ss -H -tunap` through a fixed argument array with a three-second deadline and a 4 MiB/5,000-record budget. It never captures payloads, modifies connections, contacts remote systems, or requires active-scan scope.

Each socket becomes an immutable `host_connection` observation containing the local and remote endpoint, transport/state, whether the remote address is public or local/private, and a bounded process excerpt when the operating system exposes one. The evidence is categorized as `unreviewed_connection`. Public does not mean malicious.

This supports questions such as:

- Which remote endpoints is this node communicating with?
- Which local process was associated with the socket?
- Is a destination new compared with prior snapshots?
- Which observations should an operator or later threat-intelligence correlator review?

It does not yet provide continuous scheduling, DNS/SNI attribution, byte counters, process ancestry/signing, threat-intelligence feeds, macOS/Windows adapters, eBPF, packet capture, or automatic blocking. Those are the next passive-monitoring phase. Threat categorization must preserve the same evidence ladder as advisory findings: observed connection, inferred category, externally supported reputation, and operator disposition remain separate.

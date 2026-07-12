# Observation contract and interoperability

`schemas/observation-v1.schema.json` is the stable, versioned JSON Schema for evidence leaving CortaSentry. JSONL exports contain exactly one envelope per line. Evidence and provenance remain structured JSON; timestamps are UTC RFC 3339; IP addresses are canonical; raw device material is sanitized before it reaches the contract.

The contract distinguishes observed evidence from derived assets, fingerprint candidates, changes, and findings. Consumers must not reinterpret a `tcp_connect` or `host_connection` observation as proof of maliciousness. A separate finding or operator disposition carries that claim and its supporting evidence.

Python can consume an export without a CortaSentry-specific SDK:

```python
import json

with open("observations.jsonl", encoding="utf-8") as stream:
    for line in stream:
        observation = json.loads(line)
        assert observation["schema_version"] == "cortasentry.observation.v1"
        print(observation["source"], observation["target_ip"], observation["evidence"])
```

The REST API, MCP server, Prometheus endpoint, SQLite store, and JSONL contract are independent integration surfaces. Future remote sensors must submit this semantic contract through authenticated ingestion rather than writing SQLite directly.

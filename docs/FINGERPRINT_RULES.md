# Fingerprint rules

Device rules are strict YAML with `schema_version`, semantic rule `id`/`version`, status, classification fields, required/positive/negative predicates, explanations, authorship, source, and timestamps. Predicates name a supported source type, typed field path, operator, value, weight, and explanation.

Supported operators are `equals`, `contains`, `prefix`, `suffix`, `regex`, `exists`, `in`, numeric comparison names, `port_present`, and `service_present`. v0.1 validates all names; numeric comparison execution is reserved until numeric fixtures are added. Go RE2 expressions compile at load time and are capped at 1024 bytes. Rules cannot execute code, invoke commands/network, or read arbitrary paths.

Required predicates gate a rule. Positive weights contribute with a per-source cap. Negative matches subtract. Independent source types add a bounded diversity bonus; model-specific conclusions add a small specificity bonus. Results clamp to 0–1 and are called `identification_score`. All credible candidates and predicate breakdowns are stored. Scores are not statistical probabilities.

Run `cortasentry rules validate`, `cortasentry rules test`, and `go test ./internal/fingerprint`. Reload compiles a complete replacement before atomic swap; invalid input leaves the active set unchanged.
